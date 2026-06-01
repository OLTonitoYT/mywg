import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL;

const app = express();
app.use(express.json());
app.use(cors());

// ------------------ MongoDB Models ------------------

const UserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now }
});

const CodeSchema = new mongoose.Schema({
  userId: String,
  code: String,
  expiresAt: Date
});

const User = mongoose.model("User", UserSchema);
const Code = mongoose.model("Code", CodeSchema);

// ------------------ Connect to MongoDB ------------------

mongoose.connect(MONGO_URL)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log("Mongo error:", err));

// ------------------ Console‑Style HTML ------------------

const consoleLayout = (title, body) => `
<!DOCTYPE html>
<html>
<head>
  <title>${title}</title>
  <style>
    body {
      background: black;
      color: #00ff00;
      font-family: monospace;
      padding: 20px;
    }
    input {
      background: black;
      border: 1px solid #00ff00;
      color: #00ff00;
      padding: 5px;
      width: 250px;
    }
    button {
      background: black;
      border: 1px solid #00ff00;
      color: #00ff00;
      padding: 5px 10px;
      cursor: pointer;
    }
    a { color: #00ff00; }
  </style>
</head>
<body>
${body}
</body>
</html>
`;

const loginPage = consoleLayout("Login", `
<h2>MYWG Console Login</h2>
<input id="email" placeholder="Email"><br><br>
<input id="password" type="password" placeholder="Password"><br><br>
<button onclick="login()">LOGIN</button>

<script>
async function login() {
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: email.value,
      password: password.value
    })
  });

  const data = await res.json();
  if (data.token) {
    localStorage.setItem("token", data.token);
    window.location.href = "/code";
  } else {
    alert(data.error);
  }
}
</script>
`);

const signupPage = consoleLayout("Signup", `
<h2>Create MYWG Console Account</h2>
<input id="username" placeholder="Username"><br><br>
<input id="email" placeholder="Email"><br><br>
<input id="password" type="password" placeholder="Password"><br><br>
<button onclick="signup()">SIGN UP</button>

<script>
async function signup() {
  const res = await fetch("/api/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: username.value,
      email: email.value,
      password: password.value
    })
  });

  const data = await res.json();
  if (!data.error) {
    alert("Account created!");
    window.location.href = "/login";
  } else {
    alert(data.error);
  }
}
</script>
`);

const codePage = consoleLayout("Access Code", `
<h2>MYWG Access Code</h2>
<pre id="output">Fetching code...</pre>
<button onclick="refresh()">REFRESH CODE</button>

<script>
async function refresh() {
  const token = localStorage.getItem("token");
  const res = await fetch("/api/code", {
    headers: { "Authorization": "Bearer " + token }
  });
  const data = await res.json();
  document.getElementById("output").innerText =
    "CODE: " + data.code + "\\nEXPIRES: " + data.expires;
}

refresh();
</script>
`);

// ------------------ JWT Middleware ------------------

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ------------------ Routes ------------------

app.get("/login", (req, res) => res.send(loginPage));
app.get("/signup", (req, res) => res.send(signupPage));
app.get("/code", (req, res) => res.send(codePage));

// Signup
app.post("/api/signup", async (req, res) => {
  const { username, email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  try {
    const user = await User.create({ username, email, password: hashed });
    res.json({ message: "Account created" });
  } catch {
    res.status(400).json({ error: "Email already exists" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// Generate 5‑minute code
app.get("/api/code", auth, async (req, res) => {
  const existing = await Code.findOne({ userId: req.userId });

  // If existing code is still valid, return it
  if (existing && existing.expiresAt > new Date()) {
    return res.json({
      code: existing.code,
      expires: existing.expiresAt
    });
  }

  // Otherwise create a new one
  const newCode = Math.random().toString(36).substring(2, 10).toUpperCase();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  await Code.findOneAndUpdate(
    { userId: req.userId },
    { code: newCode, expiresAt },
    { upsert: true }
  );

  res.json({
    code: newCode,
    expires: expiresAt
  });
});

// ------------------ Start Server ------------------

app.listen(PORT, () => console.log(`MYWG running on port ${PORT}`));
