const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const JWT_SECRET = "supersecretkey";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Nprotter@123",
  database: "commercial_platform"
});

db.connect(err => {
  if (err) throw err;
  console.log("MySQL Connected");
});

// ================= SIGNUP =================
app.post("/signup", upload.single("citizenship"), async (req, res) => {
  const {
    role,
    full_name,
    email,
    mobile,
    password,
    delivery_address,
    shop_name,
    shop_address,
    registration_no
  } = req.body;

  if (!role || !full_name || !email || !password)
    return res.status(400).json({ message: "Required fields missing" });

  const citizenship_image = req.file ? req.file.filename : null;
  const hashedPassword = await bcrypt.hash(password, 10);

  const checkSql =
    "SELECT email FROM customers WHERE email = ? UNION SELECT email FROM shopkeepers WHERE email = ?";

  db.query(checkSql, [email, email], (err, exists) => {
    if (err) return res.status(500).json(err);
    if (exists.length > 0)
      return res.status(409).json({ message: "Email already exists" });

    let sql, values;

    if (role === "customer") {
      sql = `INSERT INTO customers (full_name,email,mobile,password,delivery_address,citizenship_image)
             VALUES (?, ?, ?, ?, ?, ?)`;
      values = [full_name, email, mobile, hashedPassword, delivery_address, citizenship_image];
    } else if (role === "shopkeeper") {
      sql = `INSERT INTO shopkeepers
             (full_name,email,mobile,password,shop_name,shop_address,registration_no,citizenship_image)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
      values = [full_name, email, mobile, hashedPassword, shop_name, shop_address, registration_no, citizenship_image];
    } else {
      return res.status(400).json({ message: "Invalid role" });
    }

    db.query(sql, values, err => {
      if (err) return res.status(500).json(err);
      res.json({ message: "Account created successfully" });
    });
  });
});

// ================= LOGIN =================
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  const customerQuery = "SELECT id,email,password FROM customers WHERE email = ?";
  db.query(customerQuery, [email], async (err, customer) => {
    if (err) return res.status(500).json(err);

    if (customer.length > 0) {
      const match = await bcrypt.compare(password, customer[0].password);
      if (!match) return res.status(401).json({ message: "Invalid credentials" });

      const token = jwt.sign({ id: customer[0].id, role: "customer" }, JWT_SECRET, { expiresIn: "1d" });
      return res.json({ message: "Login successful", role: "customer", token });
    }

    const shopkeeperQuery = "SELECT id,email,password FROM shopkeepers WHERE email = ?";
    db.query(shopkeeperQuery, [email], async (err, shopkeeper) => {
      if (err) return res.status(500).json(err);

      if (shopkeeper.length > 0) {
        const match = await bcrypt.compare(password, shopkeeper[0].password);
        if (!match) return res.status(401).json({ message: "Invalid credentials" });

        const token = jwt.sign({ id: shopkeeper[0].id, role: "shopkeeper" }, JWT_SECRET, { expiresIn: "1d" });
        return res.json({ message: "Login successful", role: "shopkeeper", token });
      }

      return res.status(404).json({ message: "Account not found. Please sign up first" });
    });
  });
});

app.listen(3000, () => console.log("Secure server running on http://localhost:3000"));
