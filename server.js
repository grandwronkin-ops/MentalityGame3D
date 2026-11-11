const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e5 });
const PORT = Number(process.env.PORT || 3000);
const FOUNDER_USERNAME = process.env.FOUNDER_USERNAME || "founder";
const FOUNDER_PASSWORD = process.env.FOUNDER_PASSWORD || "";
const DB_FILE = path.join(__dirname, "data.json");

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

function readDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch { return { users: [], bans: [] }; }
}
let db = readDB();
function saveDB() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}
function verifyPassword(password, record) {
  const test = crypto.scryptSync(password, record.salt, 64);
  const actual = Buffer.from(record.hash, "hex");
  return actual.length === test.length && crypto.timingSafeEqual(actual, test);
}
function tokenFor(user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id, username: user.username, role: user.role,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  })).toString("base64url");
  const secret = process.env.SESSION_SECRET;
  const sig = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return payload + "." + sig;
}
function decodeToken(token) {
  if (!process.env.SESSION_SECRET || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(parts[0]).digest();
  let given;
  try { given = Buffer.from(parts[1], "base64url"); } catch { return null; }
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  try {
    const p = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    if (!p.id || p.exp < Date.now()) return null;
    const live = db.users.find(u => u.id === p.id);
    if (!live) return null;
    return { id: live.id, username: live.username, role: live.role };
  } catch { return null; }
}
function auth(req, res, next) {
  const t = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const user = decodeToken(t);
  if (!user) return res.status(401).json({ error: "Login required" });
  req.user = user; next();
}
function founderOnly(req, res, next) {
  if (req.user.role !== 7) return res.status(403).json({ error: "Founder only" });
  next();
}
function publicUser(u) { return { id: u.id, username: u.username, role: u.role }; }

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("FATAL: Set SESSION_SECRET to a random value of at least 32 characters.");
  process.exit(1);
}
if (FOUNDER_PASSWORD.length < 12) {
  console.error("FATAL: Set FOUNDER_PASSWORD to at least 12 characters.");
  process.exit(1);
}
let founder = db.users.find(u => u.username.toLowerCase() === FOUNDER_USERNAME.toLowerCase());
if (!founder) {
  const hp = hashPassword(FOUNDER_PASSWORD);
  founder = { id: crypto.randomUUID(), username: FOUNDER_USERNAME, role: 7, ...hp, createdAt: Date.now() };
  db.users.push(founder); saveDB();
} else if (founder.role !== 7) {
  founder.role = 7; saveDB();
}

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false });
app.use("/api/", limiter);

app.post("/api/register", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!/^[a-zA-Z0-9_]{3,18}$/.test(username) || password.length < 10 || password.length > 128)
    return res.status(400).json({ error: "Username: 3-18 letters/numbers/_. Password: 10-128 characters." });
  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ error: "Username already exists" });
  const hp = hashPassword(password);
  const user = { id: crypto.randomUUID(), username, role: 0, ...hp, createdAt: Date.now() };
  db.users.push(user); saveDB();
  res.json({ token: tokenFor(user), user: publicUser(user) });
});
app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user || !verifyPassword(password, user)) return res.status(401).json({ error: "Invalid username or password" });
  if (db.bans.some(b => b.userId === user.id)) return res.status(403).json({ error: "Account is banned" });
  res.json({ token: tokenFor(user), user: publicUser(user) });
});
app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));
app.get("/api/admin/users", auth, (req, res) => {
  if (req.user.role < 1) return res.status(403).json({ error: "Admin only" });
  res.json({ users: db.users.map(publicUser), bans: db.bans.map(b => ({ userId: b.userId, reason: b.reason })) });
});
app.post("/api/founder/role", auth, founderOnly, (req, res) => {
  const { userId, role } = req.body;
  const rank = Number(role);
  const target = db.users.find(u => u.id === userId);
  if (!target || target.id === founder.id || !Number.isInteger(rank) || rank < 0 || rank > 6)
    return res.status(400).json({ error: "Invalid target or rank (0-6)" });
  target.role = rank; saveDB();
  res.json({ ok: true, user: publicUser(target) });
});
app.post("/api/admin/ban", auth, (req, res) => {
  if (req.user.role < 3) return res.status(403).json({ error: "Admin L3+ required" });
  const { userId, reason } = req.body;
  const target = db.users.find(u => u.id === userId);
  if (!target || target.role >= req.user.role || target.role === 7 || target.id === req.user.id)
    return res.status(403).json({ error: "Cannot moderate this account" });
  if (!db.bans.some(b => b.userId === userId)) db.bans.push({ userId, reason: String(reason || "No reason").slice(0, 160), by: req.user.id, at: Date.now() });
  saveDB(); io.emit("system:notice", `${target.username} was banned by staff.`);
  res.json({ ok: true });
});
app.post("/api/admin/unban", auth, (req, res) => {
  if (req.user.role < 3) return res.status(403).json({ error: "Admin L3+ required" });
  const { userId } = req.body;
  db.bans = db.bans.filter(b => b.userId !== userId); saveDB(); res.json({ ok: true });
});

const online = new Map();
const roleName = r => r === 7 ? "Founder L7" : r > 0 ? `Admin L${r}` : "Player";
io.use((socket, next) => {
  const user = decodeToken(socket.handshake.auth && socket.handshake.auth.token);
  if (!user) return next(new Error("Login required"));
  if (db.bans.some(b => b.userId === user.id)) return next(new Error("Banned"));
  socket.user = user; next();
});
io.on("connection", socket => {
  const u = socket.user;
  online.set(u.id, { socketId: socket.id, username: u.username, role: u.role, x: 0, z: 0, yaw: 0 });
  socket.emit("world:players", Array.from(online.entries()).filter(([id]) => id !== u.id).map(([id,p]) => ({ id, ...p })));
  socket.broadcast.emit("world:join", { id: u.id, username: u.username, role: u.role });
  socket.on("player:move", data => {
    const p = online.get(u.id); if (!p || !data) return;
    const x = Number(data.x), z = Number(data.z), yaw = Number(data.yaw);
    if (![x,z,yaw].every(Number.isFinite) || Math.abs(x) > 500 || Math.abs(z) > 500) return;
    // Clamp displacement per update to make basic teleport cheating harder.
    const dx=x-p.x, dz=z-p.z, d=Math.hypot(dx,dz), max=1.8;
    if (d > max) { const k=max/d; p.x += dx*k; p.z += dz*k; } else { p.x=x; p.z=z; }
    p.yaw = Math.max(-Math.PI*4, Math.min(Math.PI*4, yaw));
    socket.broadcast.emit("player:moved", { id:u.id, x:p.x, z:p.z, yaw:p.yaw });
  });
  let lastChat = 0;
  socket.on("chat:message", raw => {
    const now=Date.now(); if(now-lastChat<900) return; lastChat=now;
    const message=String(raw || "").trim().slice(0,180); if(!message) return;
    io.emit("chat:message", { username:u.username, role:u.role, roleName:roleName(u.role), message, at:now });
  });
  socket.on("disconnect", () => {
    online.delete(u.id); socket.broadcast.emit("world:leave", { id:u.id });
  });
});
server.listen(PORT, "0.0.0.0", () => console.log(`MentalityGame3D online server listening on ${PORT}`));
