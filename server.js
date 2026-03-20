/**
 * ════════════════════════════════════════════════════════
 * PESHATATEIL — SERVEUR BACKEND SÉCURISÉ
 * ════════════════════════════════════════════════════════
 * 
 * Ce fichier gère :
 *  - Création de PaymentIntents Stripe (paiement sécurisé)
 *  - Webhooks Stripe (confirmation de paiement)
 *  - Envoi d'emails de confirmation (client + propriétaire)
 *  - Validation des données avant traitement
 *  - Sécurité CORS, Helmet, Rate limiting
 * 
 * AUCUNE clé secrète n'est dans ce fichier → tout est dans .env
 * ════════════════════════════════════════════════════════
 */

'use strict';

// ── Chargement des variables d'environnement ──────────────────
require('dotenv').config();

const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const stripe   = require('stripe')(process.env.STRIPE_SECRET_KEY);
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ════════════════════════════════════════
// SÉCURITÉ — MIDDLEWARE
// ════════════════════════════════════════

// Helmet : ajoute des headers HTTP de sécurité automatiquement
app.use(helmet({
  contentSecurityPolicy: false, // désactivé car on sert une API, pas du HTML
}));

// CORS : autorise uniquement votre site GitHub Pages à appeler ce serveur
const allowedOrigins = [
  process.env.CLIENT_URL,                    // https://matydelta.github.io
  'http://localhost:3000',                   // tests en local
  'http://127.0.0.1:5500',                   // Live Server VS Code
];

app.use(cors({
  origin: (origin, callback) => {
    // Autoriser les requêtes sans origin (Postman, curl) en dev uniquement
    if (!origin && process.env.NODE_ENV !== 'production') return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('CORS bloqué : origine non autorisée → ' + origin));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Rate limiting manuel simple (sans librairie supplémentaire)
const requestCounts = new Map();
function rateLimiter(maxRequests, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const data = requestCounts.get(ip) || { count: 0, start: now };

    if (now - data.start > windowMs) {
      data.count = 1;
      data.start = now;
    } else {
      data.count++;
    }
    requestCounts.set(ip, data);

    if (data.count > maxRequests) {
      return res.status(429).json({
        error: 'Trop de requêtes. Veuillez patienter quelques instants.'
      });
    }
    next();
  };
}

// ── IMPORTANT : le webhook Stripe doit recevoir le body RAW (pas JSON parsé) ──
// On exclut donc /webhook du parsing JSON global
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10kb' })); // limite la taille des requêtes

// ════════════════════════════════════════
// EMAIL — CONFIGURATION NODEMAILER
// ════════════════════════════════════════

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // Mot de passe d'application Gmail, pas le vrai mdp
  },
});

// Vérifie la connexion email au démarrage
transporter.verify((error) => {
  if (error) {
    console.warn('⚠️  Email non configuré :', error.message);
  } else {
    console.log('✅ Email configuré →', process.env.EMAIL_USER);
  }
});

// ════════════════════════════════════════
// FONCTIONS UTILITAIRES
// ════════════════════════════════════════

// Validation des données de commande
function validateOrder(body) {
  const errors = [];

  if (!body.items || !Array.isArray(body.items) || body.items.length === 0) {
    errors.push('Panier vide ou invalide');
  }
  if (!body.name || body.name.trim().length < 2) {
    errors.push('Nom invalide');
  }
  if (!body.phone || !/^[\d\s\+\-\.]{8,15}$/.test(body.phone.replace(/\s/g, ''))) {
    errors.push('Numéro de téléphone invalide');
  }
  if (!body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    errors.push('Email invalide');
  }
  if (!body.address || body.address.trim().length < 5) {
    errors.push('Adresse invalide');
  }
  if (!body.ageConfirmed || !body.cniConfirmed) {
    errors.push('Certifications majorité/CNI manquantes');
  }

  return errors;
}

// Calcul du montant côté serveur (ne jamais faire confiance au client)
function calculateAmount(items) {
  // Catalogue des prix côté serveur — source de vérité
  const PRICES = {
    1:  4200,  // Moët & Chandon — 42€ en centimes
    2:  3800,  // Glenfiddich 12
    3:  3200,  // Hendrick's Gin
    4:  8900,  // Château Margaux
    5:  2800,  // Pack Craft Beer
    6:  9500,  // Pack VIP Night
    7:  4400,  // Diplomatico 12
    8:  3600,  // Belvedere Pure
    9:  5800,  // Veuve Clicquot
    10: 2600,  // Jameson
  };

  let total = 0;
  for (const item of items) {
    const price = PRICES[item.id];
    if (!price) return null; // Produit inconnu — refus
    if (item.qty < 1 || item.qty > 20) return null; // Quantité suspecte
    total += price * item.qty;
  }

  return total; // en centimes
}

// Génère un ID de commande unique
function generateOrderId() {
  const year = new Date().getFullYear();
  const rand = Math.floor(10000 + Math.random() * 90000);
  return `PTT-${year}-${rand}`;
}

// ════════════════════════════════════════
// EMAIL — TEMPLATES
// ════════════════════════════════════════

function buildClientEmail(order) {
  const itemsList = order.items
    .map(i => `<tr>
      <td style="padding:6px 0;color:#ccc;">${i.icon || ''} ${i.name}</td>
      <td style="padding:6px 0;text-align:right;color:#fff;font-weight:bold;">×${i.qty}</td>
      <td style="padding:6px 0;text-align:right;color:#ffd700;">${i.price}€</td>
    </tr>`)
    .join('');

  return {
    from: `PeshoTaTeil <${process.env.EMAIL_USER}>`,
    to: order.email,
    subject: `✅ Commande confirmée — ${order.orderId}`,
    html: `
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="margin:0;padding:0;background:#04040a;font-family:'Segoe UI',sans-serif;">
      <div style="max-width:560px;margin:0 auto;background:#0f0f1e;border:1px solid rgba(0,245,255,.2);border-radius:8px;overflow:hidden;">
        
        <!-- Header -->
        <div style="background:linear-gradient(135deg,#ff006e,#bf00ff);padding:28px 32px;text-align:center;">
          <h1 style="margin:0;font-size:2rem;letter-spacing:6px;color:#fff;font-family:Georgia,serif;">
            PESHO<span style="color:#ffd700;">T</span>A<span style="color:#00f5ff;">T</span>EIL
          </h1>
          <p style="margin:8px 0 0;color:rgba(255,255,255,.75);font-size:.85rem;letter-spacing:2px;">
            LIVRAISON EXPRESS
          </p>
        </div>

        <!-- Corps -->
        <div style="padding:28px 32px;">
          <h2 style="color:#39ff14;margin:0 0 6px;font-size:1.2rem;letter-spacing:2px;">
            ✅ COMMANDE CONFIRMÉE
          </h2>
          <p style="color:rgba(255,255,255,.5);font-size:.85rem;margin:0 0 20px;">
            Bonjour <strong style="color:#fff;">${order.name}</strong>, votre commande a bien été reçue.
          </p>

          <!-- Numéro commande -->
          <div style="background:rgba(255,215,0,.08);border:1px solid rgba(255,215,0,.3);border-radius:6px;padding:12px 16px;margin-bottom:20px;">
            <div style="font-size:.65rem;letter-spacing:2px;color:rgba(255,255,255,.4);">NUMÉRO DE COMMANDE</div>
            <div style="font-size:1.1rem;color:#ffd700;font-weight:bold;letter-spacing:2px;margin-top:4px;">${order.orderId}</div>
          </div>

          <!-- Articles -->
          <div style="margin-bottom:20px;">
            <div style="font-size:.65rem;letter-spacing:2px;color:rgba(255,255,255,.4);margin-bottom:10px;">DÉTAIL DE LA COMMANDE</div>
            <table style="width:100%;border-collapse:collapse;">
              ${itemsList}
              <tr style="border-top:1px solid rgba(255,255,255,.1);">
                <td colspan="2" style="padding:10px 0;color:rgba(255,255,255,.5);font-size:.9rem;">Total payé</td>
                <td style="padding:10px 0;text-align:right;color:#ffd700;font-size:1.1rem;font-weight:bold;">${order.totalEuros}€</td>
              </tr>
            </table>
          </div>

          <!-- Livraison -->
          <div style="background:rgba(57,255,20,.07);border:1px solid rgba(57,255,20,.25);border-radius:6px;padding:14px 16px;margin-bottom:20px;">
            <div style="font-size:.65rem;letter-spacing:2px;color:#39ff14;margin-bottom:6px;">⏱ LIVRAISON ESTIMÉE</div>
            <div style="font-size:1.5rem;color:#fff;font-weight:bold;">${order.eta} minutes</div>
            <div style="font-size:.8rem;color:rgba(255,255,255,.45);margin-top:4px;">Adresse : ${order.address}</div>
          </div>

          <!-- CNI rappel -->
          <div style="background:rgba(255,165,0,.07);border:1px solid rgba(255,165,0,.3);border-radius:6px;padding:14px 16px;margin-bottom:24px;">
            <div style="font-size:.65rem;letter-spacing:2px;color:#ffa500;margin-bottom:6px;">🪪 RAPPEL IMPORTANT</div>
            <p style="color:rgba(255,255,255,.65);font-size:.82rem;margin:0;line-height:1.6;">
              Votre <strong style="color:#ffa500;">pièce d'identité</strong> sera vérifiée à la livraison. 
              Sans document valide, la commande ne pourra être remise.
            </p>
          </div>

          <!-- Points -->
          <div style="text-align:center;padding:12px;background:rgba(255,215,0,.05);border-radius:6px;">
            <span style="color:#ffd700;font-size:.85rem;">🏆 +${order.pts} points fidélité crédités sur votre compte</span>
          </div>
        </div>

        <!-- Footer -->
        <div style="padding:16px 32px;border-top:1px solid rgba(255,255,255,.06);text-align:center;">
          <p style="color:rgba(255,255,255,.2);font-size:.7rem;margin:0;">
            ⚠️ L'abus d'alcool est dangereux pour la santé. À consommer avec modération.<br>
            Vente interdite aux mineurs — Pièce d'identité obligatoire à la livraison.
          </p>
        </div>
      </div>
    </body>
    </html>`,
  };
}

function buildOwnerEmail(order) {
  const itemsList = order.items
    .map(i => `• ${i.icon || ''} ${i.name} ×${i.qty} — ${i.price}€`)
    .join('\n');

  return {
    from: `PeshoTaTeil <${process.env.EMAIL_USER}>`,
    to: process.env.EMAIL_USER, // vous envoie à vous-même
    subject: `🛵 NOUVELLE COMMANDE ${order.orderId} — ${order.totalEuros}€`,
    text: `
════════════════════════════════
NOUVELLE COMMANDE — PeshoTaTeil
════════════════════════════════

📦 COMMANDE : ${order.orderId}
🕐 Heure    : ${new Date().toLocaleTimeString('fr-FR')}
⏱ Livraison : dans ~${order.eta} minutes

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👤 CLIENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Nom      : ${order.name}
Tél      : ${order.phone}
Email    : ${order.email}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📍 LIVRAISON
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Adresse  : ${order.address}
Précisions : ${order.addressDetail || 'Aucune'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛒 ARTICLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${itemsList}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💰 TOTAL PAYÉ : ${order.totalEuros}€
💳 Paiement confirmé par Stripe
🆔 Payment Intent : ${order.paymentIntentId}
════════════════════════════════
    `.trim(),
  };
}

// ════════════════════════════════════════
// ROUTES API
// ════════════════════════════════════════

// Route de santé — vérifier que le serveur tourne
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'PeshoTaTeil API', timestamp: new Date().toISOString() });
});

// ── Route 1 : Créer un PaymentIntent Stripe ──────────────────
// Appelée quand le client clique sur "Confirmer & Payer"
app.post('/create-payment-intent',
  rateLimiter(10, 60 * 1000), // max 10 requêtes/minute par IP
  async (req, res) => {
    try {
      const body = req.body;

      // 1. Validation des données
      const errors = validateOrder(body);
      if (errors.length > 0) {
        return res.status(400).json({ error: 'Données invalides', details: errors });
      }

      // 2. Calcul du montant côté serveur (jamais depuis le client)
      const amountCents = calculateAmount(body.items);
      if (!amountCents || amountCents <= 0) {
        return res.status(400).json({ error: 'Panier invalide ou produits inconnus' });
      }

      const orderId = generateOrderId();
      const eta = 40 + Math.floor(Math.random() * 18);

      // 3. Création du PaymentIntent Stripe
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amountCents,
        currency: 'eur',
        automatic_payment_methods: { enabled: true },
        // Métadonnées stockées côté Stripe (utile pour le webhook)
        metadata: {
          orderId,
          customerName: body.name,
          customerPhone: body.phone,
          customerEmail: body.email,
          deliveryAddress: body.address,
          addressDetail: body.addressDetail || '',
          eta: String(eta),
          itemsCount: String(body.items.length),
        },
        // Description visible dans le dashboard Stripe
        description: `PeshoTaTeil — Commande ${orderId} — ${body.name}`,
        receipt_email: body.email,
      });

      console.log(`💳 PaymentIntent créé : ${paymentIntent.id} — ${(amountCents / 100).toFixed(2)}€`);

      // 4. Retourner le client_secret au navigateur (permet de finaliser le paiement)
      res.json({
        clientSecret: paymentIntent.client_secret,
        orderId,
        eta,
        amount: amountCents,
        publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
      });

    } catch (err) {
      console.error('❌ Erreur create-payment-intent :', err.message);
      res.status(500).json({ error: 'Erreur serveur lors de la création du paiement' });
    }
  }
);

// ── Route 2 : Webhook Stripe ──────────────────────────────────
// Stripe appelle cette route automatiquement quand un paiement est confirmé
// C'est ICI qu'on envoie les emails et qu'on confirme la commande
app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    // Vérification de la signature Stripe (évite les faux webhooks)
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('❌ Signature webhook invalide :', err.message);
    return res.status(400).json({ error: 'Signature invalide' });
  }

  // Traitement selon le type d'événement
  if (event.type === 'payment_intent.succeeded') {
    const pi = event.data.object;
    const meta = pi.metadata;

    console.log(`✅ Paiement confirmé : ${pi.id} — ${meta.orderId}`);

    // Reconstitution de la commande depuis les métadonnées Stripe
    const order = {
      orderId: meta.orderId,
      name: meta.customerName,
      phone: meta.customerPhone,
      email: meta.customerEmail,
      address: meta.deliveryAddress,
      addressDetail: meta.addressDetail,
      eta: meta.eta,
      totalEuros: (pi.amount / 100).toFixed(2),
      pts: Math.floor(pi.amount / 100),
      paymentIntentId: pi.id,
      // Les items détaillés ne sont pas dans les métadonnées (taille limitée)
      // On affiche juste le nombre
      items: [{ icon: '🛒', name: `${meta.itemsCount} article(s)`, qty: 1, price: (pi.amount / 100).toFixed(2) }],
    };

    // Envoi des emails de confirmation (client + propriétaire)
    try {
      await Promise.all([
        transporter.sendMail(buildClientEmail(order)),
        transporter.sendMail(buildOwnerEmail(order)),
      ]);
      console.log(`📧 Emails envoyés pour ${order.orderId}`);
    } catch (emailErr) {
      // L'email échoue → on log mais on ne plante pas le webhook
      console.error('⚠️  Erreur envoi email :', emailErr.message);
    }
  }

  if (event.type === 'payment_intent.payment_failed') {
    const pi = event.data.object;
    console.log(`❌ Paiement échoué : ${pi.id} — ${pi.last_payment_error?.message}`);
  }

  // Toujours répondre 200 à Stripe (sinon il réessaie)
  res.json({ received: true });
});

// ── Route 3 : Clé publique Stripe pour le frontend ───────────
// Le frontend a besoin de la clé publique pour initialiser Stripe.js
// C'est la SEULE clé Stripe qu'on peut exposer (elle est publique par design)
app.get('/config', (req, res) => {
  res.json({
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
  });
});

// ════════════════════════════════════════
// GESTION DES ERREURS GLOBALE
// ════════════════════════════════════════

// Route inconnue
app.use((req, res) => {
  res.status(404).json({ error: 'Route introuvable' });
});

// Erreur globale
app.use((err, req, res, next) => {
  console.error('❌ Erreur non gérée :', err.message);

  // Ne jamais exposer les détails d'erreur en production
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Erreur serveur interne' });
  } else {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// DÉMARRAGE
// ════════════════════════════════════════

app.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════╗');
  console.log('║   PESHATATEIL — SERVEUR DÉMARRÉ    ║');
  console.log(`║   Port     : ${PORT}                    ║`);
  console.log(`║   Env      : ${process.env.NODE_ENV || 'development'}              ║`);
  console.log(`║   Client   : ${process.env.CLIENT_URL || 'non configuré'}  ║`);
  console.log('╚════════════════════════════════════╝');
  console.log('');
});
