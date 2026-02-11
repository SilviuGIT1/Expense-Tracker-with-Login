const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = "supersecretkey";

// Connect to SQLite database
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log("Connected to SQLite database.");
  }
});

// Create Users table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

// Create Expenses table
db.run(`
  CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    amount REAL,
    date TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )
`);

// ✅ Root route (THIS is what fixes your "Cannot GET /" problem)
app.get("/", (req, res) => {
  res.send("Expense Tracker API running");
});

// Register route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (username, password) VALUES (?, ?)`,
    [username, hashedPassword],
    function (err) {
      if (err) {
        return res.status(400).json({ error: "User already exists" });
      }
      res.json({ message: "User created successfully" });
    }
  );
});

// Login route
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (!user) {
        return res.status(400).json({ error: "Invalid credentials" });
      }

      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
        return res.status(400).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign({ id: user.id }, SECRET_KEY, {
        expiresIn: "1h",
      });

      res.json({ token });
    }
  );
});

// Middleware to verify token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Add expense
app.post("/expenses", authenticateToken, (req, res) => {
  const { title, amount, date } = req.body;

  db.run(
    `INSERT INTO expenses (user_id, title, amount, date) VALUES (?, ?, ?, ?)`,
    [req.user.id, title, amount, date],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      res.json({ message: "Expense added" });
    }
  );
});

// Get expenses
app.get("/expenses", authenticateToken, (req, res) => {
  db.all(
    `SELECT * FROM expenses WHERE user_id = ?`,
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      res.json(rows);
    }
  );
});

// Start server
app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
});
