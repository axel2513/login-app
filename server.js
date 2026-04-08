const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(express.static("public"));

// 🔐 SESIONES SEGURAS
app.use(session({
  secret: "mi_secreto_super_ultra_seguro_123",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: 1000 * 60 * 60
  }
}));

const db = new Database("database.db");

// Crear tabla
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`).run();

// 🛡️ MIDDLEWARE
function auth(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ message: "No autorizado" });
  }
}

// REGISTRO
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ success: false });
  }

  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);

  if (user) {
    return res.json({ success: false, message: "Usuario ya existe" });
  }

  const hash = await bcrypt.hash(password, 10);

  db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    .run(username, hash);

  res.json({ success: true });
});

// LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ success: false });
  }

  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);

  if (!user) return res.json({ success: false });

  const valid = await bcrypt.compare(password, user.password);

  if (valid) {
    req.session.user = user.username;
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// DASHBOARD PROTEGIDO
app.get("/dashboard", auth, (req, res) => {
  res.json({ message: "Bienvenido " + req.session.user });
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.json({ message: "Sesión cerrada" });
});

// 🚀 IMPORTANTE PARA RENDER
app.listen(process.env.PORT || 3000, () => {
  console.log("Servidor PRO corriendo");
});