const express = require('express');
const path = require('path');
const cors = require('cors');
const { Server } = require('socket.io');
const http = require('http');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const JWT_SECRET = process.env.JWT_SECRET || 'cambia-esta-clave-segura';

// DB
const db = new Database('tienda.db');
db.pragma('journal_mode = WAL');

// Tablas
db.exec(`
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','vendedor'))
);
CREATE TABLE IF NOT EXISTS productos (
  codigo TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  cantidad_tienda INTEGER NOT NULL DEFAULT 0,
  cantidad_deposito INTEGER NOT NULL DEFAULT 0,
  precio REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ventas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fecha TEXT NOT NULL,
  codigo TEXT NOT NULL,
  producto TEXT NOT NULL,
  cantidad INTEGER NOT NULL,
  ubicacion TEXT NOT NULL CHECK(ubicacion IN ('tienda','deposito')),
  total REAL NOT NULL,
  usuario TEXT NOT NULL
);
`);

// Crear usuario admin por defecto si no existe
const getUserByUsername = db.prepare(`SELECT * FROM usuarios WHERE username = ?`);
const createUser = db.prepare(`INSERT INTO usuarios (username, password_hash, role) VALUES (@username, @password_hash, @role)`);
if (!getUserByUsername.get('admin')) {
  const hash = bcrypt.hashSync('admin123', 10);
  createUser.run({ username: 'admin', password_hash: hash, role: 'admin' });
  console.log('Usuario admin creado: usuario=admin, clave=admin123 (cámbiala).');
}

// Prepared statements
const stmtInsertProducto = db.prepare(`
  INSERT INTO productos (codigo, nombre, cantidad_tienda, cantidad_deposito, precio)
  VALUES (@codigo, @nombre, @cantidad_tienda, @cantidad_deposito, @precio)
`);
const stmtGetProducto = db.prepare(`SELECT * FROM productos WHERE codigo = ?`);
const stmtListProductos = db.prepare(`SELECT * FROM productos ORDER BY nombre ASC`);
const stmtUpdateProductoStock = db.prepare(`
  UPDATE productos
  SET cantidad_tienda = @cantidad_tienda,
      cantidad_deposito = @cantidad_deposito
  WHERE codigo = @codigo
`);
const stmtInsertVenta = db.prepare(`
  INSERT INTO ventas (fecha, codigo, producto, cantidad, ubicacion, total, usuario)
  VALUES (@fecha, @codigo, @producto, @cantidad, @ubicacion, @total, @usuario)
`);
const stmtListVentas = db.prepare(`SELECT * FROM ventas ORDER BY id DESC`);
const stmtCreateUser = db.prepare(`INSERT INTO usuarios (username, password_hash, role) VALUES (?, ?, ?)`);

// App y sockets
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Auth helpers
function issueToken(res, user) {
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false // pon true si usas HTTPS
  });
}
function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || (req.user.role !== role && req.user.role !== 'admin')) {
      return res.status(403).json({ error: 'No autorizado' });
    }
    next();
  };
}

// Estado en tiempo real
function broadcastEstado() {
  const productos = stmtListProductos.all();
  const ventas = stmtListVentas.all();
  const totalVentas = ventas.reduce((acc, v) => acc + v.total, 0);
  io.emit('estado', { productos, ventas, totalVentas });
}

// Rutas de autenticación
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = getUserByUsername.get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Usuario o contraseña inválidos' });
  }
  issueToken(res, user);
  res.json({ ok: true, user: { username: user.username, role: user.role } });
});

app.post('/api/auth/logout', authMiddleware, (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: { username: req.user.username, role: req.user.role } });
});

// Crear usuarios (solo admin)
app.post('/api/usuarios', authMiddleware, requireRole('admin'), (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !['admin','vendedor'].includes(role)) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }
  if (getUserByUsername.get(username)) {
    return res.status(409).json({ error: 'Usuario ya existe' });
  }
  const hash = bcrypt.hashSync(password, 10);
  stmtCreateUser.run(username, hash, role);
  res.json({ ok: true });
});

// Productos
app.get('/api/productos', authMiddleware, (req, res) => {
  res.json(stmtListProductos.all());
});
app.post('/api/productos', authMiddleware, requireRole('admin'), (req, res) => {
  const { codigo, nombre, cantidadTienda, cantidadDeposito, precio } = req.body;
  if (!codigo || !nombre || cantidadTienda == null || cantidadDeposito == null || precio == null) {
    return res.status(400).json({ error: 'Campos incompletos' });
  }
  try {
    stmtInsertProducto.run({
      codigo,
      nombre,
      cantidad_tienda: Math.max(0, parseInt(cantidadTienda, 10)),
      cantidad_deposito: Math.max(0, parseInt(cantidadDeposito, 10)),
      precio: parseFloat(precio)
    });
    broadcastEstado();
    res.json({ ok: true });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) {
      return res.status(409).json({ error: 'Código duplicado' });
    }
    console.error(e);
    res.status(500).json({ error: 'Error al guardar producto' });
  }
});

// Ventas
app.post('/api/ventas', authMiddleware, (req, res) => {
  const { codigo, cantidad, ubicacion } = req.body;
  const prod = stmtGetProducto.get(codigo);
  if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });

  const qty = parseInt(cantidad, 10);
  if (!['tienda', 'deposito'].includes(ubicacion) || isNaN(qty) || qty <= 0) {
    return res.status(400).json({ error: 'Datos de venta inválidos' });
  }

  if (ubicacion === 'tienda') {
    if (prod.cantidad_tienda < qty) return res.status(400).json({ error: 'Stock insuficiente en tienda' });
    prod.cantidad_tienda -= qty;
  } else {
    if (prod.cantidad_deposito < qty) return res.status(400).json({ error: 'Stock insuficiente en depósito' });
    prod.cantidad_deposito -= qty;
  }

  const total = qty * prod.precio;
  const fecha = new Date().toLocaleString();

  const tx = db.transaction(() => {
    stmtUpdateProductoStock.run({
      codigo: prod.codigo,
      cantidad_tienda: prod.cantidad_tienda,
      cantidad_deposito: prod.cantidad_deposito
    });
    stmtInsertVenta.run({
      fecha,
      codigo: prod.codigo,
      producto: prod.nombre,
      cantidad: qty,
      ubicacion,
      total,
      usuario: req.user.username
    });
  });

  try {
    tx();
    broadcastEstado();
    res.json({
      ok: true,
      recibo: { fecha, producto: prod.nombre, cantidad: qty, ubicacion, precio: prod.precio, total, vendedor: req.user.username }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error al registrar venta' });
  }
});

app.get('/api/ventas', authMiddleware, (req, res) => {
  res.json(stmtListVentas.all());
});

// Socket.io
io.on('connection', (socket) => {
  const productos = stmtListProductos.all();
  const ventas = stmtListVentas.all();
  const totalVentas = ventas.reduce((acc, v) => acc + v.total, 0);
  socket.emit('estado', { productos, ventas, totalVentas });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});