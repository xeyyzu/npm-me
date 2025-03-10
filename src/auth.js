const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const SECRET_KEY = "rahasia-super-kuat"; // Ganti dengan yang lebih aman
const USERS_FILE = path.join("/tmp", "users.json");

// Pastikan file users.json ada di /tmp
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

// **Fungsi untuk membaca user dari file**
function readUsers() {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
}

// **Fungsi untuk menyimpan user ke file**
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// **Fungsi Register**
function register(req, res) {
    const { username, password } = req.body;
    let users = readUsers();

    if (users.find(user => user.username === username)) {
        return res.status(400).json({ message: "Username sudah terdaftar" });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    users.push({ username, password: hashedPassword });
    saveUsers(users);

    res.json({ message: "Registrasi berhasil, silakan login" });
}

// **Fungsi Login**
function login(req, res) {
    const { username, password } = req.body;
    let users = readUsers();
    const user = users.find(u => u.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: "Username atau password salah" });
    }

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
    res.cookie("token", token, { httpOnly: true });
    res.json({ message: "Login berhasil" });
}

// **Middleware untuk proteksi halaman**
function authenticate(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: "Akses ditolak, silakan login" });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: "Token tidak valid" });
    }
}

module.exports = { register, login, authenticate };
