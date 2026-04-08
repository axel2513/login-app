const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);

const app = express();

// 🛡️ SEGURIDAD BÁSICA
app.use(express.json({ limit: "10kb" })); // evita ataques de payload
app.use(express.static("public"));

// 🔐 SESIONES (PRODUCCIÓN)
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite" }),
  secret: process.env.SESSION_SECRET || "ultra_secret_key_change_me",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // 🔥 Render usa HTTPS
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 // 1 día
  }
}));

// 🗄️ BASE DE DATOS
const db = new sqlite3.Database("database.db", (err) => {
  if (err) console.error("DB ERROR:", err);
  else console.log("✅ DB conectada");
});

// 🧱 TABLAS SEGURAS
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      balance INTEGER DEFAULT 1000
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user TEXT,
      to_user TEXT,
      amount INTEGER,
      date DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// 🛡️ MIDDLEWARE AUTH
function auth(req, res, next) {
  if (req.session.user) return next();
  return res.status(401).json({ message: "No autorizado" });
}

// 📝 REGISTER
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.json({ success: false, message: "Datos inválidos" });
    }

    db.get("SELECT * FROM users WHERE username=?", [username], async (err, user) => {
      if (user) return res.json({ success: false, message: "Usuario ya existe" });

      const hash = await bcrypt.hash(password, 10);

      db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hash],
        (err) => {
          if (err) return res.json({ success: false, message: "Error DB" });
          res.json({ success: true });
        }
      );
    });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// 🔑 LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, user) => {
    if (!user) return res.json({ success: false });

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) return res.json({ success: false });

    req.session.user = user.username;
    res.json({ success: true });
  });
});

// 📌 SESSION
app.get("/session", (req, res) => {
  res.json({
    logged: !!req.session.user,
    user: req.session.user || null
  });
});

// 💰 DASHBOARD
app.get("/dashboard", auth, (req, res) => {
  db.get(
    "SELECT username, balance FROM users WHERE username=?",
    [req.session.user],
    (err, user) => {
      if (err) return res.status(500).json({ error: true });
      res.json(user);
    }
  );
});

// 💸 ENVIAR DINERO (MEJORADO)
app.post("/send", auth, (req, res) => {
  const { to, amount } = req.body;

  if (!to || !amount || amount <= 0) {
    return res.json({ success: false, message: "Datos inválidos" });
  }

  const amountNum = parseInt(amount);

  db.get("SELECT * FROM users WHERE username=?", [req.session.user], (err, sender) => {
    db.get("SELECT * FROM users WHERE username=?", [to], (err, receiver) => {

      if (!receiver) {
        return res.json({ success: false, message: "Usuario no existe" });
      }

      if (sender.username === receiver.username) {
        return res.json({ success: false, message: "No puedes enviarte dinero a ti mismo" });
      }

      if (sender.balance < amountNum) {
        return res.json({ success: false, message: "Saldo insuficiente" });
      }

      // 🔥 TRANSACCIÓN SEGURA
      db.serialize(() => {
        db.run("BEGIN TRANSACTION");

        db.run(
          "UPDATE users SET balance = balance - ? WHERE username=?",
          [amountNum, sender.username]
        );

        db.run(
          "UPDATE users SET balance = balance + ? WHERE username=?",
          [amountNum, receiver.username]
        );

        db.run(`
          INSERT INTO transactions (from_user, to_user, amount)
          VALUES (?, ?, ?)
        `, [sender.username, receiver.username, amountNum]);

        db.run("COMMIT");
      });

      res.json({ success: true });
    });
  });
});

// 📊 HISTORIAL
app.get("/history", auth, (req, res) => {
  db.all(
    `
    SELECT * FROM transactions
    WHERE from_user=? OR to_user=?
    ORDER BY date DESC
  `,
    [req.session.user, req.session.user],
    (err, rows) => {
      if (err) return res.status(500).json({ error: true });
      res.json(rows);
    }
  );
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

// 🚀 SERVER (RENDER FIX)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Servidor corriendo en puerto " + PORT);
});