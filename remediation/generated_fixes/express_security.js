// ========================================================
// EXPRESS.JS SECURITY HARDENING & CORS MITIGATION
// Solves: Missing CSP, XFO, HSTS, Version Leak & CVE-2017-11173 (CORS Bypass)
// ========================================================

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

// 1. Disable server version disclosure banner
app.disable('x-powered-by');

// 2. Strict CORS whitelist (Fixes CVE-2017-11173 - strict anchor matching)
const ALLOWED_ORIGINS = [
  'https://yourdomain.com',
  'https://www.yourdomain.com'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Blocked by defensive CORS policy'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 3. Enforce comprehensive security headers suite
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
    },
  },
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true,
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

module.exports = app;
