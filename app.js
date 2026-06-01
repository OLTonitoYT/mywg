import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const SECRET = process.env.JWT_SECRET || "dev_fallback_secret";
const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:27017/mywg";

const app = express();
app.use(express.json());
app.use(cors());

// ---------- MongoDB & User model ----------

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    minlength: 3,
    maxlength: 32,
    trim: true
  },
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);

mongoose
  .connect(MONGO_URL)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ Mongo error:", err));

// ---------- Simple HTML pages (still minimal) ----------

const layout = (title, body) => `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>${title}</title>
</head>
<body>
  ${body}
</body>
</html>
`;

const indexHtml = layout(
  "MYWG",
  `
<h1>MYWG</h1>
<a href="/signup">Create Account</a><br>
<a href="/login">Login</a>
`
);

const signupHtml = layout(
  "Sign up - MYWG",
  `
<h2>Create MYWG Account</h2>
<input id="username" placeholder="Username"><br>
<input id="email" placeholder="Email"><br>
<input id="password" type="password" placeholder="Password"><br>
<button onclick="signup()">Sign Up</button>
<p><a href="/login">Already have an account? Login</a></p>

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
  alert(JSON.stringify(data));
  if (!data.error) window.location.href = "/login";
}
</script>
`
);

const loginHtml = layout(
  "Login - MYWG",
  `
<h2>Login to MYWG</h2>
<input id="email" placeholder="Email"><br>
<input id="password" type="password" placeholder="Password"><br>
<button onclick="login()">Login</button>
<p><a href="/signup">Need an account? Sign up</a></p>

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
    alert("Logged in!");
    window.location.href = "/dashboard";
  } else {
    alert(JSON.stringify(data));
  }
}
</script>
`
);

const dashboardHtml = layout(
  "Dashboard - MYWG",
  `
<h2>MYWG Dashboard</h2>
<p id="info">Loading...</p>
<button onclick="logout()">Logout</button>

<script>
async function loadMe() {
  const token = localStorage.getItem("token");
  if (!token) {
    document.getElementById("info").innerText = "Not logged in.";
    return;
  }

  const res = await fetch("/api/me", {
    headers: {
      "Authorization": "Bearer " + token
    }
  });

  const data = await res.json();
  if (data.error) {
    document.getElementById("info").innerText = data.error;
  } else {
    document.getElementById("info").innerText =
      "Logged in as " + data.user.email + " (username: " + data.user.username + ")";
  }
}

function logout() {
  localStorage.removeItem("token");
  alert("Logged out");
  window.location.href = "/login";
}

loadMe();
</script>
`
);

// ---------- Auth middleware ----------

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ---------- Routes (pages) ----------

app.get("/", (req, res) => res.send(indexHtml));
app.get("/signup", (req, res) => res.send(signupHtml));
app.get("/login", (req, res) => res.send(loginHtml));
app.get("/dashboard", (req, res) => res.send(dashboardHtml));

// ---------- API routes ----------

app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password: hashed
    });

    res.json({
      message: "Account created",
      user: { id: user._id, email: user.email, username: user.username }
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "7d" });
    res.json({
      message: "Logged in",
      token
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Protected route: get current user
app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user });
  } catch (err) {
    console.error("Me error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- Start server ----------

app.listen(PORT, () => {
  console.log(`🚀 MYWG running on http://localhost:${PORT}`);
});
