const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const { Pool } = require("pg");

const app = express();

app.use(express.json());
app.use(express.static("public"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(session({
  secret: "mi_secreto_super_ultra_seguro_123",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false
  }
}));

// 🧱 CREAR TABLAS AUTOMÁTICAMENTE
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,
      balance INTEGER DEFAULT 1000
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      from_user TEXT,
      to_user TEXT,
      amount INTEGER,
      date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
})();

// 🛡️ AUTH
function auth(req, res, next) {
  if (req.session.user) next();
  else res.status(401).json({ message: "No autorizado" });
}

// 📝 REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) return res.json({ success: false });

  const userExists = await pool.query(
    "SELECT * FROM users WHERE username=$1",
    [username]
  );

  if (userExists.rows.length > 0) {
    return res.json({ success: false });
  }

  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    "INSERT INTO users (username, password) VALUES ($1, $2)",
    [username, hash]
  );

  res.json({ success: true });
});

// 🔑 LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await pool.query(
    "SELECT * FROM users WHERE username=$1",
    [username]
  );

  if (user.rows.length === 0) return res.json({ success: false });

  const valid = await bcrypt.compare(password, user.rows[0].password);

  if (valid) {
    req.session.user = user.rows[0].username;
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// 📌 SESSION
app.get("/session", (req, res) => {
  if (req.session.user) {
    res.json({ logged: true, user: req.session.user });
  } else {
    res.json({ logged: false });
  }
});

// 💰 DASHBOARD
app.get("/dashboard", auth, async (req, res) => {
  const user = await pool.query(
    "SELECT username, balance FROM users WHERE username=$1",
    [req.session.user]
  );

  res.json(user.rows[0]);
});

// 💸 ENVIAR DINERO
app.post("/send", auth, async (req, res) => {
  const { to, amount } = req.body;

  if (!to || amount <= 0) {
    return res.json({ success: false });
  }

  const sender = await pool.query(
    "SELECT * FROM users WHERE username=$1",
    [req.session.user]
  );

  const receiver = await pool.query(
    "SELECT * FROM users WHERE username=$1",
    [to]
  );

  if (receiver.rows.length === 0) {
    return res.json({ success: false, message: "Usuario no existe" });
  }

  if (sender.rows[0].balance < amount) {
    return res.json({ success: false, message: "Saldo insuficiente" });
  }

  await pool.query("UPDATE users SET balance = balance - $1 WHERE username=$2", [amount, sender.rows[0].username]);

  await pool.query("UPDATE users SET balance = balance + $1 WHERE username=$2", [amount, receiver.rows[0].username]);

  await pool.query(
    "INSERT INTO transactions (from_user, to_user, amount) VALUES ($1, $2, $3)",
    [sender.rows[0].username, receiver.rows[0].username, amount]
  );

  res.json({ success: true });
});

// 📊 HISTORIAL
app.get("/history", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM transactions WHERE from_user=$1 OR to_user=$1 ORDER BY date DESC",
    [req.session.user]
  );

  res.json(result.rows);
});

// 🚪 LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get("/", (req, res) => {
  res.send("🔥 FastMoney PRO funcionando 🚀");
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Servidor corriendo");
});