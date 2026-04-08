const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(express.static("public"));

// 🔐 SESIONES
app.use(session({
  secret: "mi_secreto_super_ultra_seguro_123",
  resave: false,
  saveUninitialized: false,
}));

// 🧠 BASE DE DATOS TEMPORAL
const users = [];

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

  const exists = users.find(u => u.username === username);
  if (exists) return res.json({ success: false, message: "Usuario existe" });

  const hash = await bcrypt.hash(password, 10);

  users.push({ username, password: hash });

  res.json({ success: true });
});

// 🔑 LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ success: false });
  }

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

// 🏦 DASHBOARD
app.get("/dashboard", auth, (req, res) => {
  res.json({ message: "Bienvenido " + req.session.user });
});

// 🚪 LOGOUT 🔥 (ESTO TE FALTABA)
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true, message: "Sesión cerrada" });
  });
});

// 🏠 HOME
app.get("/", (req, res) => {
  res.send("🔥 FastMoney ONLINE 🚀");
});

// 🚀 SERVER
app.listen(process.env.PORT || 3000, () => {
  console.log("Servidor corriendo");
});