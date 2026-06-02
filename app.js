import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

// ------------------ Config ------------------

const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL;
const SECRET = process.env.JWT_SECRET;

if (!MONGO_URL) {
  throw new Error("MONGO_URL is required in environment variables");
}

if (!SECRET) {
  throw new Error("JWT_SECRET is required in environment variables");
}

// ------------------ App Setup ------------------

const app = express();
app.use(express.json());
app.use(cors());

// ------------------ MongoDB Models ------------------

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email:    { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt:{ type: Date, default: Date.now }
});

const CodeSchema = new mongoose.Schema({
  userId:   { type: String, required: true },
  code:     { type: String, required: true },
  expiresAt:{ type: Date, required: true, index: { expires: 0 } } // TTL cleanup
});

const User = mongoose.model("User", UserSchema);
const Code = mongoose.model("Code", CodeSchema);

// ------------------ Connect to MongoDB ------------------

mongoose
  .connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log("MongoDB connected"))
  .catch(err => {
    console.error("Mongo error:", err);
    process.exit(1);
  });

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
<br><br>
<a href="/signup">Create account</a>

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
    alert(data.error || "Login failed");
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
<br><br>
<a href="/login">Back to login</a>

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
<button onclick="logout()">LOGOUT</button>

<script>
async function refresh() {
  const token = localStorage.getItem("token");
  if (!token) {
    alert("No token, please log in again.");
    window.location.href = "/login";
    return;
  }

  const res = await fetch("/api/code", {
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();
  if (data.error) {
    alert(data.error);
    if (res.status === 401) {
      localStorage.removeItem("token");
      window.location.href = "/login";
    }
    return;
  }

  document.getElementById("output").innerText =
    "CODE: " + data.code + "\\nEXPIRES: " + new Date(data.expires).toLocaleString();
}

function logout() {
  localStorage.removeItem("token");
  window.location.href = "/login";
}

refresh();
</script>
`);

// ------------------ JWT Middleware ------------------

function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ------------------ Routes ------------------

// Root: redirect to login so you don't get "Cannot GET /"
app.get("/", (req, res) => res.redirect("/login"));

app.get("/login", (req, res) => res.send(loginPage));
app.get("/signup", (req, res) => res.send(signupPage));
app.get("/code", (req, res) => res.send(codePage));

// Signup
app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashed });

    res.json({ message: "Account created" });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      // generic error to avoid user enumeration
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Generate 5‑minute code
app.get("/api/code", auth, async (req, res) => {
  try {
    const existing = await Code.findOne({ userId: req.userId });

    // If existing code is still valid, return it
    if (existing && existing.expiresAt > new Date()) {
      return res.json({
        code: existing.code,
        expires: existing.expiresAt
      });
    }

    // Otherwise create a new one (crypto‑secure)
    const newCode = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8 hex chars
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await Code.findOneAndUpdate(
      { userId: req.userId },
      { code: newCode, expiresAt },
      { upsert: true, new: true }
    );

    res.json({
      code: newCode,
      expires: expiresAt
    });
  } catch (err) {
    console.error("Code error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ------------------ Start Server ------------------

app.listen(PORT, () => console.log(`MYWG running on port ${PORT}`));
