const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(express.static("public"));

app.use(session({
  secret: "mi_secreto_super_ultra_seguro_123",
  resave: false,
  saveUninitialized: false,
}));

// 🧠 BASE DE DATOS TEMPORAL
const users = [];

// AUTH
function auth(req, res, next) {
  if (req.session.user) next();
  else res.status(401).json({ message: "No autorizado" });
}

// 📝 REGISTER (ahora con saldo)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const exists = users.find(u => u.username === username);
  if (exists) return res.json({ success: false });

  const hash = await bcrypt.hash(password, 10);

  users.push({
    username,
    password: hash,
    balance: 1000 // 💸 saldo inicial
  });

  res.json({ success: true });
});

// 🔑 LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) return res.json({ success: false });

  const valid = await bcrypt.compare(password, user.password);

  if (valid) {
    req.session.user = username;
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// 💰 VER BALANCE
app.get("/balance", auth, (req, res) => {
  const user = users.find(u => u.username === req.session.user);
  res.json({ balance: user.balance });
});

// 💸 ENVIAR DINERO
app.post("/send", auth, (req, res) => {
  const { to, amount } = req.body;

  const sender = users.find(u => u.username === req.session.user);
  const receiver = users.find(u => u.username === to);

  if (!receiver) {
    return res.json({ success: false, message: "Usuario no existe" });
  }

  if (sender.balance < amount) {
    return res.json({ success: false, message: "Saldo insuficiente" });
  }

  sender.balance -= amount;
  receiver.balance += amount;

  res.json({ success: true });
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

app.listen(process.env.PORT || 3000, () => {
  console.log("Servidor corriendo");
});