require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const dataDir = path.join(__dirname, "data");
const authRoot = path.join(dataDir, "whatsapp-auth");
fs.mkdirSync(authRoot, { recursive: true });
const db = new Database(path.join(dataDir, "waguri.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wallet (
  user_jid TEXT PRIMARY KEY, coins INTEGER NOT NULL DEFAULT 0, last_daily INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS bots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir }),
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: isProduction, maxAge: 1000*60*60*24*7 }
}));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 20, standardHeaders: true, legacyHeaders: false });
app.use("/api/register", authLimiter); app.use("/api/login", authLimiter);

function safeUser(u){ return {id:u.id,username:u.username,email:u.email,created_at:u.created_at}; }
function requireAuth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:"Inicia sesión para continuar."}); next(); }
function validEmail(email){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function ownedBot(req,res,next){
  const bot = db.prepare("SELECT id,user_id,name,phone,status,created_at FROM bots WHERE id=? AND user_id=?")
    .get(Number(req.params.id), req.session.userId);
  if(!bot) return res.status(404).json({error:"Bot no encontrado."});
  req.bot=bot; next();
}

// Baileys sockets are kept in memory; auth files are per-user/per-bot on this server.
const connections = new Map();
function connKey(userId, botId){ return `${userId}:${botId}`; }
function safeAuthPath(userId, botId) {
  // IDs are numeric and derived from authenticated database records.
  return path.join(authRoot, `u${Number(userId)}-b${Number(botId)}`);
}
async function startWhatsApp(userId, bot) {
  const key = connKey(userId, bot.id);
  const current = connections.get(key);
  if (current && current.status === "connecting") return current;
  if (current && current.status === "connected") return current;

  const state = { status:"connecting", qr:null, error:null, socket:null, updatedAt:Date.now() };
  connections.set(key,state);
  db.prepare("UPDATE bots SET status='pending' WHERE id=? AND user_id=?").run(bot.id,userId);

  try {
    const baileys = await import("@whiskeysockets/baileys");
    const makeWASocket = baileys.default;
    const { useMultiFileAuthState, DisconnectReason, Browsers } = baileys;
    const authDir = safeAuthPath(userId,bot.id);
    fs.mkdirSync(authDir,{recursive:true});
    const { state:authState, saveCreds } = await useMultiFileAuthState(authDir);
    const sock = makeWASocket({
      auth: authState,
      browser: Browsers ? Browsers.ubuntu("Waguri") : ["Waguri","Chrome","120.0.0"],
      printQRInTerminal: false,
      markOnlineOnConnect: false,
      syncFullHistory: false
    });
    state.socket=sock;
    sock.ev.on("creds.update", saveCreds);
    // Minimal expandable command engine. Commands are only triggered by an explicit prefix.
    sock.ev.on("messages.upsert", async ({ messages, type }) => {
      if (type !== "notify") return;
      for (const msg of messages || []) {
        try {
          if (!msg.message || msg.key.fromMe) continue;
          const jid = msg.key.remoteJid;
          if (!jid || jid === "status@broadcast") continue;
          const text = (msg.message.conversation || msg.message.extendedTextMessage?.text || msg.message.imageMessage?.caption || "").trim();
          if (!text.startsWith(".")) continue;
          const [rawCommand, ...args] = text.slice(1).split(/\s+/);
          const command = (rawCommand || "").toLowerCase();
          const sender = msg.key.participant || jid;
          const wallet = db.prepare("SELECT coins,last_daily FROM wallet WHERE user_jid=?").get(sender) || {coins:0,last_daily:0};
          let reply = null;
          if (["menu","help","allmenu"].includes(command)) {
            reply = `╭─ 🌸 *WAGURI BOT* 🌸 ─╮\n\n*Anime:* .hug .kiss .dance .pat .smile .cry\n*Economía:* .balance .daily .work\n*Juegos:* .ppt <piedra|papel|tijera>\n*Info:* .ping .status .menu\n\nMás módulos se añadirán en próximas versiones.`;
          } else if (["ping","p"].includes(command)) reply = `🏓 *Pong!* Waguri está activo.`;
          else if (["status","info"].includes(command)) reply = `🌸 *Waguri*\nEstado: activo\nMotor: Baileys\nComandos básicos habilitados.`;
          else if (["balance","bal"].includes(command)) reply = `🪙 Tienes *${wallet.coins} WaguriCoins*.`;
          else if (command === "daily") {
            const now=Date.now(), day=86400000;
            if(now-wallet.last_daily < day) reply=`⏳ Ya reclamaste tu recompensa. Vuelve en ${Math.ceil((day-(now-wallet.last_daily))/3600000)} h.`;
            else { db.prepare("INSERT INTO wallet(user_jid,coins,last_daily) VALUES(?,100,?) ON CONFLICT(user_jid) DO UPDATE SET coins=coins+100,last_daily=excluded.last_daily").run(sender,now); reply="🎁 Recibiste *100 WaguriCoins* por tu recompensa diaria."; }
          } else if (["work","w"].includes(command)) {
            const earned=25+Math.floor(Math.random()*76);
            db.prepare("INSERT INTO wallet(user_jid,coins) VALUES(?,?) ON CONFLICT(user_jid) DO UPDATE SET coins=coins+excluded.coins").run(sender,earned);
            reply=`🧰 Trabajaste en la cafetería de anime y ganaste *${earned} WaguriCoins*.`;
          } else if (["hug","kiss","dance","pat","smile","cry","wave","happy","sad","blush","laugh"].includes(command)) {
            const target=args[0] ? args.join(" ") : "el chat";
            const actions={hug:"abrazó a",kiss:"le dio un beso amistoso a",dance:"bailó con",pat:"le dio una palmadita a",smile:"sonrió a",cry:"se puso triste junto a",wave:"saludó a",happy:"se alegró con",sad:"se entristeció con",blush:"se sonrojó por",laugh:"se rio con"};
            reply=`🌸 @${target.replace(/[^0-9]/g,"") || "todos"} ${actions[command] || command}.`;
          } else if (command === "ppt") {
            const choice=(args[0]||"").toLowerCase(), choices=["piedra","papel","tijera"];
            if(!choices.includes(choice)) reply="Uso: .ppt piedra, .ppt papel o .ppt tijera";
            else {const bot=choices[Math.floor(Math.random()*3)];const win=choice===bot?"Empate":((choice==="piedra"&&bot==="tijera")||(choice==="papel"&&bot==="piedra")||(choice==="tijera"&&bot==="papel"))?"¡Ganaste!":"Ganó Waguri";reply=`🎮 Tú: ${choice}\nWaguri: ${bot}\n${win}`;}
          }
          if (reply) await sock.sendMessage(jid,{text:reply},{quoted:msg});
        } catch (commandError) { console.error("Command handler:",commandError); }
      }
    });
    sock.ev.on("connection.update", async update => {
      if (update.qr) { state.qr=update.qr; state.status="qr"; state.updatedAt=Date.now(); }
      if (update.connection === "open") {
        state.status="connected"; state.qr=null; state.error=null; state.updatedAt=Date.now();
        db.prepare("UPDATE bots SET status='connected' WHERE id=? AND user_id=?").run(bot.id,userId);
      }
      if (update.connection === "close") {
        state.qr=null; state.updatedAt=Date.now();
        const code = update.lastDisconnect?.error?.output?.statusCode;
        const loggedOut = code === DisconnectReason.loggedOut;
        state.status = loggedOut ? "logged_out" : "disconnected";
        state.error = loggedOut ? "La sesión se cerró desde WhatsApp. Elimina la sesión y vuelve a vincular." : "La conexión se cerró. Puedes volver a intentar.";
        db.prepare("UPDATE bots SET status='pending' WHERE id=? AND user_id=?").run(bot.id,userId);
        connections.delete(key);
      }
    });
    return state;
  } catch (err) {
    connections.delete(key);
    db.prepare("UPDATE bots SET status='pending' WHERE id=? AND user_id=?").run(bot.id,userId);
    throw err;
  }
}
async function disconnectWhatsApp(userId, botId, removeAuth=false) {
  const key=connKey(userId,botId);
  const state=connections.get(key);
  if(state?.socket) {
    try { state.socket.end(undefined); } catch(_) {}
  }
  connections.delete(key);
  db.prepare("UPDATE bots SET status='pending' WHERE id=? AND user_id=?").run(botId,userId);
  if(removeAuth) {
    const authDir=safeAuthPath(userId,botId);
    fs.rmSync(authDir,{recursive:true,force:true});
  }
}

app.get("/api/me",(req,res)=>{
  if(!req.session.userId) return res.json({user:null});
  const u=db.prepare("SELECT id,username,email,created_at FROM users WHERE id=?").get(req.session.userId);
  if(!u){req.session.destroy(()=>{});return res.json({user:null});}
  res.json({user:safeUser(u)});
});
app.post("/api/register",async(req,res)=>{
  const username=String(req.body.username||"").trim(), email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
  if(!/^[a-zA-Z0-9_-]{3,24}$/.test(username)) return res.status(400).json({error:"El usuario debe tener 3–24 caracteres: letras, números, _ o -."});
  if(!validEmail(email)) return res.status(400).json({error:"Escribe un correo válido."});
  if(password.length<10) return res.status(400).json({error:"La contraseña debe tener al menos 10 caracteres."});
  if(password.length>200) return res.status(400).json({error:"La contraseña es demasiado larga."});
  const hash=await bcrypt.hash(password,12);
  try{
    const result=db.prepare("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)").run(username,email,hash);
    req.session.userId=Number(result.lastInsertRowid);
    res.status(201).json({user:{id:Number(result.lastInsertRowid),username,email},message:"Cuenta creada."});
  }catch(e){if(String(e.code).startsWith("SQLITE_CONSTRAINT"))return res.status(409).json({error:"Ese usuario o correo ya existe."});console.error(e);res.status(500).json({error:"No se pudo crear la cuenta."});}
});
app.post("/api/login",async(req,res)=>{
  const identifier=String(req.body.identifier||"").trim().toLowerCase(),password=String(req.body.password||"");
  const u=db.prepare("SELECT * FROM users WHERE lower(username)=? OR email=?").get(identifier,identifier);
  if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Usuario/correo o contraseña incorrectos."});
  req.session.regenerate(err=>{if(err)return res.status(500).json({error:"No se pudo iniciar sesión."});req.session.userId=u.id;res.json({user:safeUser(u),message:"Sesión iniciada."});});
});
app.post("/api/logout",(req,res)=>{req.session.destroy(err=>{if(err)return res.status(500).json({error:"No se pudo cerrar sesión."});res.clearCookie("connect.sid");res.json({message:"Sesión cerrada."});});});

app.get("/api/dashboard",requireAuth,(req,res)=>{
  const bots=db.prepare("SELECT id,name,phone,status,created_at FROM bots WHERE user_id=? ORDER BY id DESC").all(req.session.userId);
  res.json({bots:bots.map(b=>({...b,connection:connections.get(connKey(req.session.userId,b.id))?.status || (b.status==="connected"?"connected":"disconnected")})),
    stats:{totalBots:bots.length,connected:bots.filter(b=>b.status==="connected").length,pending:bots.filter(b=>b.status!=="connected").length},service:"Waguri dashboard"});
});
app.post("/api/bots",requireAuth,(req,res)=>{
  const name=String(req.body.name||"").trim(),phone=String(req.body.phone||"").trim();
  if(name.length<2||name.length>40)return res.status(400).json({error:"El nombre debe tener entre 2 y 40 caracteres."});
  if(phone.length>24)return res.status(400).json({error:"El teléfono es demasiado largo."});
  const result=db.prepare("INSERT INTO bots(user_id,name,phone,status) VALUES(?,?,?,'pending')").run(req.session.userId,name,phone);
  res.status(201).json({bot:db.prepare("SELECT id,name,phone,status,created_at FROM bots WHERE id=?").get(result.lastInsertRowid)});
});
app.delete("/api/bots/:id",requireAuth,ownedBot,async(req,res)=>{
  await disconnectWhatsApp(req.session.userId,req.bot.id,true);
  db.prepare("DELETE FROM bots WHERE id=? AND user_id=?").run(req.bot.id,req.session.userId);
  res.json({message:"Bot eliminado."});
});
app.post("/api/bots/:id/connect",requireAuth,ownedBot,async(req,res)=>{
  try{
    const state=await startWhatsApp(req.session.userId,req.bot);
    res.json({status:state.status,message:"Conexión iniciada. Espera el QR."});
  }catch(e){console.error("Baileys start error:",e);res.status(500).json({error:"No se pudo iniciar Baileys. Revisa versión de Node y logs del servidor."});}
});
app.get("/api/bots/:id/connection",requireAuth,ownedBot,async(req,res)=>{
  const state=connections.get(connKey(req.session.userId,req.bot.id));
  let qrImage=null;
  if(state?.qr){
    try { const QRCode=require("qrcode"); qrImage=await QRCode.toDataURL(state.qr,{width:280,margin:2}); } catch(e){ console.error(e); }
  }
  res.json({status:state?.status || (req.bot.status==="connected"?"connected":"disconnected"),qr:qrImage,error:state?.error||null});
});
app.post("/api/bots/:id/disconnect",requireAuth,ownedBot,async(req,res)=>{
  await disconnectWhatsApp(req.session.userId,req.bot.id,false);
  res.json({message:"Desconexión solicitada."});
});
app.post("/api/bots/:id/forget-session",requireAuth,ownedBot,async(req,res)=>{
  await disconnectWhatsApp(req.session.userId,req.bot.id,true);
  res.json({message:"Credenciales locales eliminadas. Vuelve a vincular para conectar."});
});
app.get("/api/health",(_req,res)=>res.json({ok:true,name:"Waguri"}));
app.get("*",(_req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Waguri disponible en http://localhost:${PORT}`));
