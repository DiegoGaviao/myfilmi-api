const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const DEMO = process.env.DEMO === '1' || process.env.DEMO === 'true';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const rawOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
const ALLOWED_ORIGINS = rawOrigins.length ? rawOrigins : ['https://myfilmi.com'];

app.set('trust proxy', 1);

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // permite curl/health checks
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by CORS'), false);
  },
  credentials: true,
}));

// health check
app.get('/healthz', (req, res) => res.status(200).send('ok'));

// util: pegar token do header Authorization: Bearer ... ou cookie "token"
function getToken(req) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (m) return m[1];
  if (req.cookies && req.cookies.token) return req.cookies.token;
  return null;
}

// rota de demo para emitir token fake (só com DEMO=1)
app.get('/api/mock-login', (req, res) => {
  if (!DEMO) return res.status(404).json({ error: 'disabled' });
  const demoUser = {
    id: 'u_demo',
    name: 'Demo User',
    email: 'demo@myfilmi.com',
    picture: 'https://i.pravatar.cc/120?u=demo'
  };
  const token = jwt.sign({ sub: demoUser.id, user: demoUser }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: demoUser });
});

// /api/me: se tiver token válido, devolve user; se DEMO, devolve demo; senão 401
app.get('/api/me', (req, res) => {
  const token = getToken(req);
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      return res.json(payload.user || { id: payload.sub });
    } catch (e) {
      // token inválido → cai no DEMO/401
    }
  }
  if (DEMO) {
    return res.json({ id: 'u_demo', name: 'Demo User', email: 'demo@myfilmi.com', picture: 'https://i.pravatar.cc/120?u=demo' });
  }
  return res.status(401).json({ error: 'unauthorized' });
});

// placeholder do callback OAuth (ajuste depois)
app.get('/auth/facebook/callback', (req, res) => {
  return res.status(200).send('Facebook callback placeholder. Configure e redirecione ao front.');
});

app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(', ') || '(none)'}`);
});
