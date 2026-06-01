import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const SECRET = "MYWG_SUPER_SECRET_KEY";
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB model
const UserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log("Mongo error:", err));

// HTML pages
const indexHtml = `
<h1>MYWG</h1>
<a href="/signup">Create Account</a><br>
<a href="/login">Login</a>
`;

const signupHtml = `
<h2>Create MYWG Account</h2>
<input id="username" placeholder="Username"><br>
<input id="email" placeholder="Email"><br>
<input id="password" type="password" placeholder="Password"><br>
<button onclick="signup()">Sign Up</button>

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
`;

const loginHtml = `
<h2>Login to MYWG</h2>
<input id="email" placeholder="Email"><br>
<input id="password" type="password" placeholder="Password"><br>
<button onclick="login()">Login</button>

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
  } else {
    alert(JSON.stringify(data));
  }
}
</script>
`;

// Routes
app.get("/", (req, res) => res.send(indexHtml));
app.get("/signup", (req, res) => res.send(signupHtml));
app.get("/login", (req, res) => res.send(loginHtml));

app.post("/api/signup", async (req, res) => {
  const { username, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  try {
    const user = await User.create({ username, email, password: hashed });
    res.json({ message: "Account created", user: { id: user._id, email: user.email } });
  } catch {
    res.status(400).json({ error: "Email already exists" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "7d" });
  res.json({ message: "Logged in", token });
});

app.listen(PORT, () => console.log("MYWG running on port", PORT));
