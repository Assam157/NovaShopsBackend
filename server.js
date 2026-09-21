 import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import Product from './models/product.js';

const {
  PORT = 5000,
  MONGO_URI = 'mongodb+srv://Maitreya:killdill12@cluster0.sk6ugig.mongodb.net/myDatabase?retryWrites=true&w=majority/visiting_card',
  JWT_SECRET = 'change-me',
  ADMIN_USERNAME = 'admin',
  ADMIN_PASSWORD = 'admin12',
  CORS_ORIGINS = 'http://localhost:3000,http://localhost:3001'
} = process.env;

const ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 10);

const app = express();
app.set('trust proxy', 1);

/* ------------------------------------------------------------------ */
/* Core middleware                                                    */
/* ------------------------------------------------------------------ */
const allowedOrigins = CORS_ORIGINS.split(',').map((s) => s.trim());
/* ------------------------------------------------------------------ */
/* CORS — never throws, always sends ACAO for allowed origins         */
/* ------------------------------------------------------------------ */
 

console.log('🌐 Allowed CORS origins:', allowedOrigins);

const corsOptions = {
  origin: (origin, cb) => {
    // No Origin header (curl, Postman, server-to-server): allow
    if (!origin) return cb(null, true);

    // Exact whitelist match
    if (allowedOrigins.includes(origin)) return cb(null, true);

    // Allow any *.onrender.com subdomain
    try {
      const { hostname } = new URL(origin);
      if (hostname.endsWith('.onrender.com')) return cb(null, true);
    } catch {
      // malformed origin — deny below
    }

    // Deny silently (no ACAO header). Do NOT throw — throwing breaks preflight.
    console.warn(`⛔ CORS denied: ${origin}`);
    return cb(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Explicit preflight handler — guarantees OPTIONS returns 200 with ACAO
app.options('*', cors(corsOptions));
app.use(express.json());

/* ------------------------------------------------------------------ */
/* Uploads directory + multer                                         */
/* ------------------------------------------------------------------ */
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const ALLOWED_MIME = ['image/jpeg', 'image/png'];

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = file.mimetype === 'image/png' ? '.png' : '.jpg';
    const name = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_MIME.includes(file.mimetype)) {
      return cb(new Error('Only JPEG and PNG images are allowed'));
    }
    cb(null, true);
  }
});

// Serve uploaded images at /uploads/<file>
app.use('/uploads', express.static(UPLOAD_DIR));

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function requireDb(_req, res, next) {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      message: 'Database unavailable. Please try again in a moment.'
    });
  }
  next();
}

/* ------------------------------------------------------------------ */
/* DB connection                                                      */
/* ------------------------------------------------------------------ */
mongoose
  .connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

mongoose.connection.on('disconnected', () => console.warn('⚠️  MongoDB disconnected'));
mongoose.connection.on('reconnected', () => console.log('✅ MongoDB reconnected'));

/* ------------------------------------------------------------------ */
/* Auth middleware                                                    */
/* ------------------------------------------------------------------ */
function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    req.admin = payload;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
}

/* ================================================================== */
/* ROUTES                                                             */
/* ================================================================== */

/* ---------- Public ------------------------------------------------- */
app.get('/api/health', (_req, res) => {
  const dbState = ['disconnected', 'connected', 'connecting', 'disconnecting'][
    mongoose.connection.readyState
  ] || 'unknown';
  res.json({ ok: true, db: dbState });
});

app.get(
  '/api/products',
  requireDb,
  asyncHandler(async (_req, res) => {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  })
);

app.get(
  '/api/products/:id',
  requireDb,
  asyncHandler(async (req, res) => {
    let product;
    try {
      product = await Product.findById(req.params.id);
    } catch {
      return res.status(400).json({ message: 'Invalid product id' });
    }
    if (!product) return res.status(404).json({ message: 'Product not found' });
    res.json(product);
  })
);

/* ---------- Auth --------------------------------------------------- */
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  const okUser = username === ADMIN_USERNAME;
  const okPass = bcrypt.compareSync(password || '', ADMIN_PASSWORD_HASH);
  if (!okUser || !okPass) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }
  const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, username });
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({ username: req.admin.username });
});

/* ---------- Admin: image upload ----------------------------------- */
/*  ⚠️  MUST be defined BEFORE the 404 catch-all at the bottom.        */
app.post(
  '/api/upload',
  requireAdmin,
  (req, res, next) => {
    upload.single('image')(req, res, (err) => {
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ message: 'Image must be 5MB or smaller' });
        }
        return res.status(400).json({ message: err.message || 'Upload failed' });
      }
      next();
    });
  },
  (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.status(201).json({ url });
  }
);

/* ---------- Admin: product CRUD ----------------------------------- */
app.post(
  '/api/products',
  requireAdmin,
  requireDb,
  asyncHandler(async (req, res) => {
    const { name, category, price, stock, image, description } = req.body || {};
    if (!name || String(name).trim() === '') {
      return res.status(400).json({ message: 'Product name is required' });
    }
    const product = await Product.create({
      name: String(name).trim(),
      category: (category || 'General').toString().trim() || 'General',
      price: Math.max(0, Number(price) || 0),
      stock: Math.max(0, parseInt(stock, 10) || 0),
      image: (image || '').toString().trim(),
      description: (description || '').toString().trim()
    });
    res.status(201).json(product);
  })
);

app.put(
  '/api/products/:id',
  requireAdmin,
  requireDb,
  asyncHandler(async (req, res) => {
    const { name, category, price, stock, image, description } = req.body || {};
    const update = {};
    if (name !== undefined) update.name = String(name).trim();
    if (category !== undefined) update.category = (category || 'General').toString().trim();
    if (price !== undefined) update.price = Math.max(0, Number(price) || 0);
    if (stock !== undefined) update.stock = Math.max(0, parseInt(stock, 10) || 0);
    if (image !== undefined) update.image = (image || '').toString().trim();
    if (description !== undefined) update.description = (description || '').toString().trim();

    let updated;
    try {
      updated = await Product.findByIdAndUpdate(req.params.id, update, { new: true });
    } catch {
      return res.status(400).json({ message: 'Invalid product id' });
    }
    if (!updated) return res.status(404).json({ message: 'Product not found' });
    res.json(updated);
  })
);

app.patch(
  '/api/products/:id/stock',
  requireAdmin,
  requireDb,
  asyncHandler(async (req, res) => {
    const stock = Math.max(0, parseInt(req.body?.stock, 10) || 0);
    let updated;
    try {
      updated = await Product.findByIdAndUpdate(req.params.id, { stock }, { new: true });
    } catch {
      return res.status(400).json({ message: 'Invalid product id' });
    }
    if (!updated) return res.status(404).json({ message: 'Product not found' });
    res.json(updated);
  })
);

app.delete(
  '/api/products/:id',
  requireAdmin,
  requireDb,
  asyncHandler(async (req, res) => {
    let removed;
    try {
      removed = await Product.findByIdAndDelete(req.params.id);
    } catch {
      return res.status(400).json({ message: 'Invalid product id' });
    }
    if (!removed) return res.status(404).json({ message: 'Product not found' });
    res.json(removed);
  })
);

/* ================================================================== */
/* 404 + error handler — MUST be the LAST middleware                  */
/* ================================================================== */
app.use((_req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('💥 Unhandled route error:', err);
  if (res.headersSent) return;

  if (err.name === 'ValidationError') {
    const first = Object.values(err.errors || {})[0];
    return res.status(400).json({ message: first?.message || 'Validation error' });
  }
  if (err.name === 'CastError') {
    return res.status(400).json({ message: 'Invalid id format' });
  }

  const status = err.status || 500;
  res.status(status).json({ message: err.message || 'Internal server error' });
});

/* ================================================================== */
app.listen(PORT, () => {
  console.log(`✅ Backend running on http://localhost:${PORT}`);
});
