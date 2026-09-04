const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const multer = require('multer');
const Stripe = require('stripe');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.JWT_SECRET || 'dev-only-change-this-secret';
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || (IS_PROD ? 'true' : 'false')) === 'true';
const MIN_WITHDRAWAL = Number(process.env.MIN_WITHDRAWAL || 100);
const HOLD_DAYS = Number(process.env.COMMISSION_HOLD_DAYS || 7);
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const stripe = STRIPE_KEY ? new Stripe(STRIPE_KEY) : null;

const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(__dirname, 'uploads');
fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(UPLOADS, { recursive: true });
const db = new Database(path.join(DATA, 'promo.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'member',
 status TEXT NOT NULL DEFAULT 'pending',
 code TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 description TEXT DEFAULT '',
 image TEXT DEFAULT '',
 price REAL NOT NULL DEFAULT 0,
 commission_rate REAL NOT NULL DEFAULT 0,
 stock INTEGER NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS media (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 product_id INTEGER NOT NULL,
 type TEXT NOT NULL,
 title TEXT NOT NULL,
 url TEXT NOT NULL,
 caption TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS clicks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 product_id INTEGER NOT NULL,
 visitor_id TEXT,
 ip_hash TEXT,
 user_agent TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id),
 FOREIGN KEY(product_id) REFERENCES products(id)
);
CREATE INDEX IF NOT EXISTS idx_clicks_user_product ON clicks(user_id,product_id);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 click_id INTEGER,
 order_no TEXT NOT NULL UNIQUE,
 customer_name TEXT NOT NULL,
 customer_email TEXT NOT NULL,
 phone TEXT NOT NULL,
 address TEXT NOT NULL,
 subtotal REAL NOT NULL,
 shipping_fee REAL NOT NULL DEFAULT 0,
 total REAL NOT NULL,
 commission REAL NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'pending',
 payment_status TEXT NOT NULL DEFAULT 'unpaid',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id),
 FOREIGN KEY(click_id) REFERENCES clicks(id)
);
CREATE TABLE IF NOT EXISTS order_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL,
 product_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 price REAL NOT NULL,
 qty INTEGER NOT NULL,
 commission_rate REAL NOT NULL,
 commission REAL NOT NULL,
 FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
 FOREIGN KEY(product_id) REFERENCES products(id)
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL UNIQUE,
 provider TEXT NOT NULL,
 provider_payment_id TEXT,
 amount REAL NOT NULL,
 currency TEXT NOT NULL DEFAULT 'thb',
 status TEXT NOT NULL DEFAULT 'pending',
 checkout_url TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS webhook_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 provider TEXT NOT NULL,
 event_id TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wallets (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL UNIQUE,
 available REAL NOT NULL DEFAULT 0,
 pending REAL NOT NULL DEFAULT 0,
 paid REAL NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS wallet_transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 type TEXT NOT NULL,
 amount REAL NOT NULL,
 reference TEXT,
 description TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS withdrawals (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 amount REAL NOT NULL,
 method TEXT NOT NULL,
 account_name TEXT NOT NULL,
 account_number TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 note TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 processed_at TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);

function setting(k, fallback='') { const r=db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r ? r.value : fallback; }
function setSetting(k,v){ db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k,String(v)); }
function code(){ return crypto.randomBytes(5).toString('hex').toUpperCase(); }
function orderNo(){ return 'PH' + new Date().toISOString().replace(/\D/g,'').slice(0,14) + crypto.randomBytes(3).toString('hex').toUpperCase(); }
function cookieOptions(maxAge){ return { httpOnly:true, sameSite:'lax', secure:COOKIE_SECURE, path:'/', ...(maxAge ? {maxAge} : {}) }; }
function parseCookies(req){ const raw=req.headers.cookie||''; return Object.fromEntries(raw.split(';').filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i).trim(),decodeURIComponent(x.slice(i+1))]})); }
function issueToken(user){ return jwt.sign({id:user.id,role:user.role},SECRET,{expiresIn:'7d'}); }
function auth(req,res,next){ try { const c=parseCookies(req); const token=c.ph_token || (req.headers.authorization||'').replace(/^Bearer\s+/,''); if(!token) return res.status(401).json({error:'กรุณาเข้าสู่ระบบ'}); req.user=jwt.verify(token,SECRET); next(); } catch { res.status(401).json({error:'เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่'}); } }
function adminOnly(req,res,next){ if(req.user.role!=='admin') return res.status(403).json({error:'ไม่มีสิทธิ์'}); next(); }
function safeUser(id){ return db.prepare('SELECT id,name,email,role,status,code,created_at FROM users WHERE id=?').get(id); }
function ensureWallet(userId){ db.prepare('INSERT OR IGNORE INTO wallets(user_id) VALUES(?)').run(userId); return db.prepare('SELECT * FROM wallets WHERE user_id=?').get(userId); }
function absolute(req,p){ return `${APP_URL}${p}`; }
function originGuard(req,res,next){ if(['POST','PATCH','PUT','DELETE'].includes(req.method)){ const origin=req.get('origin'); if(origin && origin!==APP_URL) return res.status(403).json({error:'คำขอจากแหล่งที่ไม่อนุญาต'}); } next(); }

// Stripe webhook MUST receive raw body before express.json.
app.post('/api/webhooks/stripe', express.raw({type:'application/json'}), (req,res)=>{
  if(!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(503).send('Stripe webhook is not configured');
  let event;
  try { event=stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET); }
  catch(e){ return res.status(400).send(`Webhook Error: ${e.message}`); }
  const exists=db.prepare('SELECT id FROM webhook_events WHERE event_id=?').get(event.id);
  if(exists) return res.json({received:true,duplicate:true});
  try {
    db.prepare('INSERT INTO webhook_events(provider,event_id) VALUES(?,?)').run('stripe',event.id);
    if(event.type==='checkout.session.completed') settleStripeSession(event.data.object);
    if(event.type==='checkout.session.expired') expireStripeSession(event.data.object);
    res.json({received:true});
  } catch(e){ console.error(e); res.status(500).json({error:'Webhook processing failed'}); }
});

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'1mb'}));
app.use(originGuard);
app.use('/uploads',express.static(UPLOADS,{maxAge:'7d'}));
app.use(express.static(path.join(__dirname,'public')));

// Basic in-memory rate limiter for sensitive endpoints.
const hits=new Map();
function rateLimit(limit,windowMs){ return (req,res,next)=>{ const key=(req.ip||'x')+req.path; const now=Date.now(); const a=(hits.get(key)||[]).filter(t=>t>now-windowMs); if(a.length>=limit) return res.status(429).json({error:'ทำรายการถี่เกินไป กรุณาลองใหม่ภายหลัง'}); a.push(now); hits.set(key,a); next(); }; }

app.post('/api/register',rateLimit(8,10*60*1000),async(req,res)=>{
  const {name,email,password}=req.body||{};
  if(!name || !/^\S+@\S+\.\S+$/.test(String(email||'')) || String(password||'').length<8) return res.status(400).json({error:'กรุณากรอกชื่อ อีเมล และรหัสผ่านอย่างน้อย 8 ตัวอักษร'});
  try { const hash=await bcrypt.hash(password,12); let c=code(); while(db.prepare('SELECT 1 FROM users WHERE code=?').get(c)) c=code(); const r=db.prepare('INSERT INTO users(name,email,password,code) VALUES(?,?,?,?)').run(String(name).trim(),String(email).trim().toLowerCase(),hash,c); ensureWallet(r.lastInsertRowid); res.json({ok:true,message:'สมัครสมาชิกสำเร็จ รอผู้ดูแลอนุมัติ'}); }
  catch(e){ res.status(400).json({error:e.code==='SQLITE_CONSTRAINT_UNIQUE'?'อีเมลนี้ถูกใช้แล้ว':'สมัครสมาชิกไม่สำเร็จ'}); }
});
app.post('/api/login',rateLimit(10,10*60*1000),async(req,res)=>{
  const {email,password}=req.body||{}; const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(email||'').trim().toLowerCase());
  if(!u || !(await bcrypt.compare(String(password||''),u.password))) return res.status(401).json({error:'อีเมลหรือรหัสผ่านไม่ถูกต้อง'});
  if(u.status==='suspended') return res.status(403).json({error:'บัญชีถูกระงับ'});
  res.cookie('ph_token',issueToken(u),cookieOptions(7*24*60*60*1000)); res.json({user:safeUser(u.id)});
});
app.post('/api/logout',(req,res)=>{res.clearCookie('ph_token',cookieOptions());res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json(safeUser(req.user.id)));

app.get('/api/products',auth,(req,res)=>res.json(db.prepare('SELECT id,name,description,image,price,commission_rate,stock FROM products WHERE active=1 ORDER BY id DESC').all()));
app.get('/api/products/:id',auth,(req,res)=>{const p=db.prepare('SELECT id,name,description,image,price,commission_rate,stock FROM products WHERE id=? AND active=1').get(req.params.id);if(!p)return res.status(404).json({error:'ไม่พบสินค้า'});res.json({...p,media:db.prepare('SELECT id,type,title,url,caption FROM media WHERE product_id=? ORDER BY id DESC').all(p.id)});});
app.get('/api/products/:id/media',auth,(req,res)=>res.json(db.prepare('SELECT id,type,title,url,caption FROM media WHERE product_id=? ORDER BY id DESC').all(req.params.id)));

// Affiliate click + cookie attribution.
app.get('/r/:code/:productId',(req,res)=>{
  const u=db.prepare("SELECT id,code,status FROM users WHERE code=? AND role='member'").get(req.params.code);
  const p=db.prepare('SELECT id FROM products WHERE id=? AND active=1').get(req.params.productId);
  if(!u || u.status!=='approved' || !p) return res.redirect('/?ref=invalid');
  const visitor=crypto.randomUUID(); const ipHash=crypto.createHash('sha256').update((req.ip||'')+SECRET).digest('hex');
  const r=db.prepare('INSERT INTO clicks(user_id,product_id,visitor_id,ip_hash,user_agent) VALUES(?,?,?,?,?)').run(u.id,p.id,visitor,ipHash,req.get('user-agent')||'');
  res.cookie('ph_click',String(r.lastInsertRowid),{httpOnly:true,sameSite:'lax',secure:COOKIE_SECURE,maxAge:30*24*60*60*1000,path:'/'});
  res.redirect(`/shop.html?product=${encodeURIComponent(p.id)}`);
});
app.post('/api/clicks',auth,(req,res)=>{const {productId}=req.body||{};const p=db.prepare('SELECT id FROM products WHERE id=? AND active=1').get(productId);if(!p)return res.status(404).json({error:'ไม่พบสินค้า'});const r=db.prepare('INSERT INTO clicks(user_id,product_id,visitor_id) VALUES(?,?,?)').run(req.user.id,p.id,crypto.randomUUID());res.json({clickId:Number(r.lastInsertRowid),link:absolute(req,`/r/${safeUser(req.user.id).code}/${p.id}`)});});

// Public checkout.
app.get('/shop.html',(req,res)=>res.sendFile(path.join(__dirname,'public','shop.html')));
app.post('/api/public/orders',rateLimit(20,10*60*1000),async(req,res)=>{
  const {items,customer}=req.body||{};
  if(!Array.isArray(items)||!items.length||!customer?.name||!customer?.email||!customer?.phone||!customer?.address) return res.status(400).json({error:'ข้อมูล Checkout ไม่ครบ'});
  if(items.length>20) return res.status(400).json({error:'ตะกร้ามีสินค้ามากเกินไป'});
  const clean=[]; for(const x of items){const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(Number(x.productId));const qty=Math.max(1,Math.min(99,Number(x.qty)||1));if(!p)return res.status(400).json({error:'มีสินค้าที่ไม่พร้อมขาย'});if(p.stock>0&&qty>p.stock)return res.status(400).json({error:`สินค้า ${p.name} มีจำนวนไม่พอ`});clean.push({p,qty});}
  const subtotal=clean.reduce((s,x)=>s+x.p.price*x.qty,0); const shipping=subtotal>=1000?0:50; const total=subtotal+shipping;
  const clickId=Number(parseCookies(req).ph_click||0)||null; const click=clickId?db.prepare('SELECT c.*,u.status FROM clicks c JOIN users u ON u.id=c.user_id WHERE c.id=?').get(clickId):null; const affiliate=click&&click.status==='approved'?click:null;
  const commission=affiliate?clean.filter(x=>x.p.id===click.product_id).reduce((s,x)=>s+x.p.price*x.qty*x.p.commission_rate/100,0):0;
  const tx=db.transaction(()=>{
    const o=db.prepare('INSERT INTO orders(user_id,click_id,order_no,customer_name,customer_email,phone,address,subtotal,shipping_fee,total,commission) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(affiliate?.user_id||null,affiliate?.id||null,orderNo(),String(customer.name).trim(),String(customer.email).trim().toLowerCase(),String(customer.phone).trim(),String(customer.address).trim(),subtotal,shipping,total,commission);
    const orderId=Number(o.lastInsertRowid); const ins=db.prepare('INSERT INTO order_items(order_id,product_id,name,price,qty,commission_rate,commission) VALUES(?,?,?,?,?,?,?)'); for(const x of clean) ins.run(orderId,x.p.id,x.p.name,x.p.price,x.qty,x.p.commission_rate,(x.p.id===click?.product_id?x.p.price*x.qty*x.p.commission_rate/100:0));
    return {orderId,orderNo:db.prepare('SELECT order_no FROM orders WHERE id=?').get(orderId).order_no};
  });
  let pay={provider:'sandbox',status:'pending',checkoutUrl:absolute(req,`/sandbox-pay.html?order=${tx.orderId}`)};
  if(stripe){
    try { const session=await stripe.checkout.sessions.create({mode:'payment',customer_email:customer.email,line_items:clean.map(x=>({price_data:{currency:'thb',product_data:{name:x.p.name},unit_amount:Math.round(x.p.price*100)},quantity:x.qty})),shipping_address_collection:{allowed_countries:['TH']},success_url:`${APP_URL}/payment-success.html?order=${tx.orderId}&session_id={CHECKOUT_SESSION_ID}`,cancel_url:`${APP_URL}/shop.html?cancelled=1`,metadata:{orderId:String(tx.orderId)}}); pay={provider:'stripe',status:'pending',checkoutUrl:session.url,providerPaymentId:session.id}; db.prepare('INSERT INTO payments(order_id,provider,provider_payment_id,amount,status,checkout_url) VALUES(?,?,?,?,?,?)').run(tx.orderId,'stripe',session.id,total,'pending',session.url); }
    catch(e){ console.error('Stripe create failed',e); return res.status(500).json({error:'สร้างหน้าชำระเงินไม่สำเร็จ'}); }
  } else db.prepare('INSERT INTO payments(order_id,provider,amount,status,checkout_url) VALUES(?,?,?,?,?)').run(tx.orderId,'sandbox',total,'pending',pay.checkoutUrl);
  res.cookie('ph_click','',{httpOnly:true,sameSite:'lax',secure:COOKIE_SECURE,maxAge:0,path:'/'});
  res.json({ok:true,orderId:tx.orderId,orderNo:tx.orderNo,total,payment:pay});
});
app.get('/api/public/orders/:orderNo',(req,res)=>{const o=db.prepare('SELECT id,order_no,customer_name,subtotal,shipping_fee,total,status,payment_status,created_at FROM orders WHERE order_no=?').get(req.params.orderNo);if(!o)return res.status(404).json({error:'ไม่พบออเดอร์'});res.json({...o,items:db.prepare('SELECT name,price,qty FROM order_items WHERE order_id=?').all(o.id)});});

// Sandbox only for development/demo.
app.post('/api/sandbox/pay/:id',async(req,res)=>{if(IS_PROD&&stripe)return res.status(404).json({error:'Sandbox disabled'});const o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);if(!o)return res.status(404).json({error:'ไม่พบออเดอร์'});settleOrder(o.id,'sandbox_'+crypto.randomBytes(6).toString('hex'));res.json({ok:true});});
app.get('/sandbox-pay.html',(req,res)=>res.sendFile(path.join(__dirname,'public','sandbox-pay.html')));
app.get('/payment-success.html',(req,res)=>res.sendFile(path.join(__dirname,'public','payment-success.html')));

function settleStripeSession(session){ settleOrder(Number(session.metadata?.orderId),session.id); }
function expireStripeSession(session){ const id=Number(session.metadata?.orderId); if(id) db.prepare("UPDATE orders SET payment_status='expired',status='cancelled' WHERE id=? AND payment_status='unpaid'").run(id); }
function settleOrder(orderId,paymentId){
  const tx=db.transaction(()=>{
    const o=db.prepare('SELECT * FROM orders WHERE id=?').get(orderId); if(!o||o.payment_status==='paid')return;
    db.prepare("UPDATE orders SET payment_status='paid',status='confirmed' WHERE id=?").run(orderId);
    db.prepare("UPDATE payments SET status='paid',provider_payment_id=COALESCE(provider_payment_id,?) WHERE order_id=?").run(paymentId,orderId);
    if(o.user_id && o.commission>0){ensureWallet(o.user_id);db.prepare('UPDATE wallets SET pending=pending+?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').run(o.commission,o.user_id);db.prepare('INSERT INTO wallet_transactions(user_id,type,amount,reference,description) VALUES(?,?,?,?,?)').run(o.user_id,'commission_pending',o.commission,o.order_no,`คอมมิชชันจากออเดอร์ ${o.order_no}`);}
  }); tx();
}

app.get('/api/dashboard',auth,(req,res)=>{const w=ensureWallet(req.user.id);const clicks=db.prepare('SELECT COUNT(*) c FROM clicks WHERE user_id=?').get(req.user.id).c;const orders=db.prepare("SELECT COUNT(*) c FROM orders WHERE user_id=? AND payment_status='paid'").get(req.user.id).c;const sales=db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders WHERE user_id=? AND payment_status='paid'").get(req.user.id).s;res.json({clicks,orders,sales,commissionAvailable:w.available,commissionPending:w.pending,paid:w.paid});});
app.get('/api/orders',auth,(req,res)=>res.json(db.prepare(`SELECT o.order_no,o.customer_name,o.total,o.commission,o.status,o.payment_status,o.created_at FROM orders o WHERE o.user_id=? ORDER BY o.id DESC`).all(req.user.id)));
app.get('/api/links',auth,(req,res)=>{ const rows=db.prepare(`SELECT p.id,p.name,p.image,p.price,p.commission_rate,(SELECT COUNT(*) FROM clicks c WHERE c.user_id=? AND c.product_id=p.id) clicks,(SELECT COUNT(DISTINCT o.id) FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.user_id=? AND oi.product_id=p.id) orders,(SELECT COALESCE(SUM(o.total),0) FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.user_id=? AND oi.product_id=p.id AND o.payment_status='paid') sales FROM products p WHERE p.active=1 ORDER BY p.id DESC`).all(req.user.id,req.user.id,req.user.id).map(x=>({...x,link:absolute(req,`/r/${safeUser(req.user.id).code}/${x.id}`)})); res.json(rows); });
app.get('/api/wallet',auth,(req,res)=>res.json({wallet:ensureWallet(req.user.id),transactions:db.prepare('SELECT type,amount,reference,description,created_at FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT 100').all(req.user.id),withdrawals:db.prepare('SELECT id,amount,method,account_name,account_number,status,note,created_at,processed_at FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.user.id)}));
app.post('/api/withdrawals',auth,rateLimit(10,60*60*1000),(req,res)=>{const {amount,method,accountName,accountNumber}=req.body||{};const n=Number(amount);if(!Number.isFinite(n)||n<MIN_WITHDRAWAL)return res.status(400).json({error:`ยอดถอนขั้นต่ำ ${MIN_WITHDRAWAL.toLocaleString()} บาท`});if(!['bank','promptpay'].includes(method)||!accountName||!accountNumber)return res.status(400).json({error:'ข้อมูลการถอนเงินไม่ครบ'});const tx=db.transaction(()=>{const w=ensureWallet(req.user.id);if(w.available<n)throw new Error('ยอดคงเหลือไม่พอ');db.prepare('UPDATE wallets SET available=available-?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').run(n,req.user.id);const r=db.prepare('INSERT INTO withdrawals(user_id,amount,method,account_name,account_number) VALUES(?,?,?,?,?)').run(req.user.id,n,method,String(accountName).trim(),String(accountNumber).trim());db.prepare('INSERT INTO wallet_transactions(user_id,type,amount,reference,description) VALUES(?,?,?,?,?)').run(req.user.id,'withdrawal',-n,`WD-${r.lastInsertRowid}`,'ขอถอนเงิน');return r.lastInsertRowid;});try{res.json({ok:true,id:Number(tx)})}catch(e){res.status(400).json({error:e.message})}});

// Admin
app.get('/api/admin/stats',auth,adminOnly,(req,res)=>res.json({users:db.prepare("SELECT COUNT(*) c FROM users WHERE role='member'").get().c,pendingUsers:db.prepare("SELECT COUNT(*) c FROM users WHERE role='member' AND status='pending'").get().c,orders:db.prepare("SELECT COUNT(*) c FROM orders WHERE payment_status='paid'").get().c,sales:db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders WHERE payment_status='paid'").get().s,commission:db.prepare("SELECT COALESCE(SUM(commission),0) s FROM orders WHERE payment_status='paid'").get().s,withdrawals:db.prepare("SELECT COUNT(*) c FROM withdrawals WHERE status='pending'").get().c}));
app.get('/api/admin/users',auth,adminOnly,(req,res)=>res.json(db.prepare('SELECT id,name,email,status,code,created_at FROM users WHERE role=\'member\' ORDER BY id DESC').all()));
app.patch('/api/admin/users/:id/status',auth,adminOnly,(req,res)=>{const allowed=['pending','approved','suspended'];if(!allowed.includes(req.body?.status))return res.status(400).json({error:'สถานะไม่ถูกต้อง'});db.prepare("UPDATE users SET status=? WHERE id=? AND role='member'").run(req.body.status,req.params.id);res.json({ok:true})});
app.get('/api/admin/orders',auth,adminOnly,(req,res)=>res.json(db.prepare(`SELECT o.id,o.order_no,o.customer_name,o.customer_email,o.total,o.commission,o.status,o.payment_status,o.created_at,u.name member FROM orders o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 500`).all()));
app.patch('/api/admin/orders/:id/status',auth,adminOnly,(req,res)=>{const allowed=['pending','confirmed','cancelled','shipped','completed'];if(!allowed.includes(req.body?.status))return res.status(400).json({error:'สถานะไม่ถูกต้อง'});db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status,req.params.id);res.json({ok:true})});
app.get('/api/admin/products',auth,adminOnly,(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.post('/api/admin/products',auth,adminOnly,(req,res)=>{const {name,description,image,price,commissionRate,stock}=req.body||{};if(!name||Number(price)<0||Number(commissionRate)<0)return res.status(400).json({error:'ข้อมูลสินค้าไม่ถูกต้อง'});const r=db.prepare('INSERT INTO products(name,description,image,price,commission_rate,stock) VALUES(?,?,?,?,?,?)').run(String(name).trim(),description||'',image||'',Number(price),Number(commissionRate),Number(stock)||0);res.json({id:Number(r.lastInsertRowid)})});
app.patch('/api/admin/products/:id',auth,adminOnly,(req,res)=>{const x=req.body||{};db.prepare('UPDATE products SET name=COALESCE(?,name),description=COALESCE(?,description),image=COALESCE(?,image),price=COALESCE(?,price),commission_rate=COALESCE(?,commission_rate),stock=COALESCE(?,stock),active=COALESCE(?,active) WHERE id=?').run(x.name??null,x.description??null,x.image??null,x.price==null?null:Number(x.price),x.commissionRate==null?null:Number(x.commissionRate),x.stock==null?null:Number(x.stock),x.active==null?null:(x.active?1:0),req.params.id);res.json({ok:true})});
app.post('/api/admin/media',auth,adminOnly,(req,res)=>{const {productId,type,title,url,caption}=req.body||{};if(!productId||!type||!title||!url)return res.status(400).json({error:'ข้อมูลสื่อไม่ครบ'});const r=db.prepare('INSERT INTO media(product_id,type,title,url,caption) VALUES(?,?,?,?,?)').run(Number(productId),type,title,url,caption||'');res.json({id:Number(r.lastInsertRowid)})});
app.delete('/api/admin/media/:id',auth,adminOnly,(req,res)=>{db.prepare('DELETE FROM media WHERE id=?').run(req.params.id);res.json({ok:true})});
app.get('/api/admin/withdrawals',auth,adminOnly,(req,res)=>res.json(db.prepare(`SELECT w.*,u.name member,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC`).all()));
app.patch('/api/admin/withdrawals/:id/status',auth,adminOnly,(req,res)=>{const allowed=['pending','processing','paid','rejected'];if(!allowed.includes(req.body?.status))return res.status(400).json({error:'สถานะไม่ถูกต้อง'});const tx=db.transaction(()=>{const w=db.prepare('SELECT * FROM withdrawals WHERE id=?').get(req.params.id);if(!w)throw new Error('ไม่พบรายการ');if(w.status===req.body.status)return; if(req.body.status==='paid'&&w.status!=='paid'){db.prepare('UPDATE wallets SET paid=paid+?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').run(w.amount,w.user_id);} if(req.body.status==='rejected'&&w.status!=='rejected'){db.prepare('UPDATE wallets SET available=available+?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').run(w.amount,w.user_id);db.prepare('INSERT INTO wallet_transactions(user_id,type,amount,reference,description) VALUES(?,?,?,?,?)').run(w.user_id,'withdrawal_refund',w.amount,`WD-${w.id}`,'คืนยอดจากคำขอถอนที่ถูกปฏิเสธ');} db.prepare('UPDATE withdrawals SET status=?,processed_at=CASE WHEN ? IN (\'paid\',\'rejected\') THEN CURRENT_TIMESTAMP ELSE processed_at END WHERE id=?').run(req.body.status,req.body.status,req.params.id);});try{tx();res.json({ok:true})}catch(e){res.status(400).json({error:e.message})}});

// Optional media upload endpoint (local disk for MVP; use S3/R2 in scale-out production).
const upload=multer({dest:UPLOADS,limits:{fileSize:10*1024*1024},fileFilter:(req,file,cb)=>cb(null,/^image\/(png|jpe?g|webp)$/.test(file.mimetype)||/^video\/mp4$/.test(file.mimetype))});
app.post('/api/admin/upload',auth,adminOnly,upload.single('file'),(req,res)=>{if(!req.file)return res.status(400).json({error:'ไม่พบไฟล์หรือชนิดไฟล์ไม่รองรับ'});const ext=path.extname(req.file.originalname).toLowerCase()||({ 'image/png':'.png','image/jpeg':'.jpg','image/webp':'.webp','video/mp4':'.mp4'}[req.file.mimetype]||'');const dest=req.file.path+ext;fs.renameSync(req.file.path,dest);res.json({url:absolute(req,`/uploads/${path.basename(dest)}`),type:req.file.mimetype.startsWith('video')?'video':'image'});});

// Release held commissions automatically after hold period, unless order is cancelled.
function releaseCommissions(){
  const cutoff=new Date(Date.now()-HOLD_DAYS*86400000).toISOString().replace('T',' ').slice(0,19);
  const rows=db.prepare(`SELECT o.id,o.order_no,o.user_id,o.commission FROM orders o WHERE o.payment_status='paid' AND o.status!='cancelled' AND o.commission>0 AND o.created_at<=? AND NOT EXISTS(SELECT 1 FROM wallet_transactions t WHERE t.type='commission_released' AND t.reference=o.order_no)`).all(cutoff);
  const tx=db.transaction(()=>{for(const o of rows){ensureWallet(o.user_id);db.prepare('UPDATE wallets SET pending=MAX(0,pending-?),available=available+?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').run(o.commission,o.commission,o.user_id);db.prepare('INSERT INTO wallet_transactions(user_id,type,amount,reference,description) VALUES(?,?,?,?,?)').run(o.user_id,'commission_released',o.commission,o.order_no,`คอมมิชชันพร้อมถอนจาก ${o.order_no}`);}}); if(rows.length)tx();
}
setInterval(releaseCommissions,60*60*1000); releaseCommissions();

// Seed admin + demo products.
(async()=>{let a=db.prepare('SELECT id FROM users WHERE email=?').get('admin@promohub.local');if(!a){const hash=await bcrypt.hash('admin123',12);let c=code();db.prepare('INSERT INTO users(name,email,password,role,status,code) VALUES(?,?,?,?,?,?)').run('PROMO HUB Admin','admin@promohub.local',hash,'admin','approved',c);}const count=db.prepare('SELECT COUNT(*) c FROM products').get().c;if(!count){const ins=db.prepare('INSERT INTO products(name,description,image,price,commission_rate,stock) VALUES(?,?,?,?,?,?)');ins.run('Blackmores Bio Magnesium Advanced + D3','แมกนีเซียม + D3 สำหรับดูแลสุขภาพ','',850,10,100);ins.run('Blackmores Fish Oil 1000','น้ำมันปลา','',650,10,100);ins.run('Blackmores Vitamin C 1000','วิตามินซี','',590,8,100);}})();

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`PROMO HUB 2.3 running at ${APP_URL}`));
