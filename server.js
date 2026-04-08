const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(express.static("public"));

app.use(session({
  secret: "mi_secreto_super_ultra_seguro_123",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false
  }
}));

// 🗄️ BASE DE DATOS
const db = new Database("database.db");

// 🧱 TABLAS
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    balance INTEGER DEFAULT 1000
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT,
    to_user TEXT,
    amount INTEGER,
    date DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// 🛡️ AUTH
function auth(req, res, next) {
  if (req.session.user) next();
  else res.status(401).json({ message: "No autorizado" });
}

// 📝 REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ success: false });
  }

  const exists = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (exists) return res.json({ success: false });

  const hash = await bcrypt.hash(password, 10);

  db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    .run(username, hash);

  res.json({ success: true });
});

// 🔑 LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

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

// 💰 BALANCE
app.get("/balance", auth, (req, res) => {
  const user = db.prepare("SELECT balance FROM users WHERE username=?")
    .get(req.session.user);

  res.json({ balance: user.balance });
});

// 💸 ENVIAR DINERO (PRO)
app.post("/send", auth, (req, res) => {
  const { to, amount } = req.body;

  if (!to || !amount || amount <= 0) {
    return res.json({ success: false, message: "Datos inválidos" });
  }

  const sender = db.prepare("SELECT * FROM users WHERE username=?")
    .get(req.session.user);

  const receiver = db.prepare("SELECT * FROM users WHERE username=?")
    .get(to);

  if (!receiver) {
    return res.json({ success: false, message: "Usuario no existe" });
  }

  if (sender.username === receiver.username) {
    return res.json({ success: false, message: "No puedes enviarte dinero a ti mismo" });
  }

  if (sender.balance < amount) {
    return res.json({ success: false, message: "Saldo insuficiente" });
  }

  const transaction = db.transaction(() => {
    db.prepare("UPDATE users SET balance = balance - ? WHERE username=?")
      .run(amount, sender.username);

    db.prepare("UPDATE users SET balance = balance + ? WHERE username=?")
      .run(amount, receiver.username);

    db.prepare(`
      INSERT INTO transactions (from_user, to_user, amount)
      VALUES (?, ?, ?)
    `).run(sender.username, receiver.username, amount);
  });

  transaction();

  res.json({ success: true });
});

// 📊 HISTORIAL
app.get("/history", auth, (req, res) => {
  const history = db.prepare(`
    SELECT * FROM transactions
    WHERE from_user=? OR to_user=?
    ORDER BY date DESC
  `).all(req.session.user, req.session.user);

  res.json(history);
});

// 🏦 DASHBOARD
app.get("/dashboard", auth, (req, res) => {
  res.json({ message: "Bienvenido " + req.session.user });
});

// 🚪 LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

// 🏠 HOME
app.get("/", (req, res) => {
  res.send("🔥 FastMoney BANK 💸 ONLINE 🚀");
});

// 🚀 SERVER
app.listen(process.env.PORT || 3000, () => {
  console.log("Servidor corriendo");
});