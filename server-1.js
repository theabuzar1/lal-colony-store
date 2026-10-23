// Lal Colony General Store - zero-dependency backend (Node 18+)
// Run: ADMIN_PASSWORD=yourpass node server.js
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const PORT=process.env.PORT||3000,ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"change-me";
const DIR=path.join(__dirname,"data"),FILE=path.join(DIR,"db.json"),PUB=path.join(__dirname,"public");
fs.mkdirSync(DIR,{recursive:true});
let db={users:[],orders:[],secret:crypto.randomBytes(32).toString("hex")};
try{db=Object.assign(db,JSON.parse(fs.readFileSync(FILE,"utf8")))}catch(e){}
const save=()=>{fs.writeFileSync(FILE+".tmp",JSON.stringify(db));fs.renameSync(FILE+".tmp",FILE)};save();
const sign=(p)=>{const b=Buffer.from(JSON.stringify(p)).toString("base64url");return b+"."+crypto.createHmac("sha256",db.secret).update(b).digest("base64url")};
const verify=(t)=>{try{const[b,s]=String(t).split(".");const ok=crypto.createHmac("sha256",db.secret).update(b).digest("base64url");if(s.length!==ok.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(ok)))return null;const p=JSON.parse(Buffer.from(b,"base64url"));return p.exp>Date.now()?p:null}catch(e){return null}};
const hash=(pw,salt)=>crypto.scryptSync(pw,salt,32).toString("hex");
const tries={};const limited=(ip)=>{const n=Date.now(),a=(tries[ip]=(tries[ip]||[]).filter(x=>n-x<600000));a.push(n);return a.length>15};
const send=(res,code,obj)=>{res.writeHead(code,{"Content-Type":"application/json"});res.end(JSON.stringify(obj))};
const body=(req)=>new Promise((ok)=>{let d="";req.on("data",c=>{d+=c;if(d.length>1e6)req.destroy()});req.on("end",()=>{try{ok(JSON.parse(d||"{}"))}catch(e){ok({})}})});
const clean=(s,n)=>String(s||"").trim().slice(0,n);
const auth=(req,role)=>{const p=verify((req.headers.authorization||"").replace("Bearer ",""));return p&&p.role===role?p:null};
const MIME={".html":"text/html",".js":"text/javascript",".css":"text/css",".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".webp":"image/webp",".svg":"image/svg+xml"};

http.createServer(async(req,res)=>{
  const url=req.url.split("?")[0],ip=req.socket.remoteAddress;
  if(url.startsWith("/api/")){
    try{
    if(req.method==="POST"&&(url==="/api/register"||url==="/api/login"||url==="/api/admin/login")&&limited(ip))return send(res,429,{error:"Too many attempts. Try again in a few minutes."});
    if(req.method==="POST"&&url==="/api/register"){
      const b=await body(req),name=clean(b.name,60),phone=clean(b.phone,10),pw=String(b.password||"");
      if(!name)return send(res,400,{error:"Please enter your name."});
      if(!/^[6-9]\d{9}$/.test(phone))return send(res,400,{error:"Enter a valid 10-digit mobile number."});
      if(pw.length<6)return send(res,400,{error:"Password must be at least 6 characters."});
      if(db.users.find(u=>u.phone===phone))return send(res,409,{error:"This number is already registered. Please log in."});
      const salt=crypto.randomBytes(16).toString("hex");db.users.push({name,phone,salt,hash:hash(pw,salt),created:Date.now()});save();
      return send(res,200,{token:sign({role:"user",phone,exp:Date.now()+30*864e5}),user:{name,phone}});
    }
    if(req.method==="POST"&&url==="/api/login"){
      const b=await body(req),u=db.users.find(x=>x.phone===clean(b.phone,10));
      if(!u||hash(String(b.password||""),u.salt)!==u.hash)return send(res,401,{error:"Wrong mobile number or password."});
      return send(res,200,{token:sign({role:"user",phone:u.phone,exp:Date.now()+30*864e5}),user:{name:u.name,phone:u.phone}});
    }
    if(req.method==="POST"&&url==="/api/orders"){
      const p=auth(req,"user");if(!p)return send(res,401,{error:"Please log in to place an order."});
      const b=await body(req),u=db.users.find(x=>x.phone===p.phone);if(!u)return send(res,401,{error:"Please log in again."});
      const items=(Array.isArray(b.items)?b.items:[]).slice(0,100).map(i=>({name:clean(i.name,80),unit:clean(i.unit,30),price:Math.max(0,+i.price||0),qty:Math.min(99,Math.max(1,parseInt(i.qty)||1))}));
      const address=clean(b.address,300);if(!items.length||!address)return send(res,400,{error:"Cart or address is empty."});
      const o={id:"LC"+Date.now().toString().slice(-6),time:Date.now(),name:u.name,phone:u.phone,items,total:items.reduce((s,i)=>s+i.price*i.qty,0),address,landmark:clean(b.landmark,120),location:/^https:\/\/www\.google\.com\/maps\?q=[-\d.,]+$/.test(b.location||"")?b.location:"",payment:"Cash on delivery",status:"New"};
      db.orders.push(o);save();return send(res,200,{id:o.id,total:o.total});
    }
    if(req.method==="GET"&&url==="/api/my-orders"){
      const p=auth(req,"user");if(!p)return send(res,401,{error:"Please log in."});
      return send(res,200,{orders:db.orders.filter(o=>o.phone===p.phone).reverse()});
    }
    if(req.method==="POST"&&url==="/api/admin/login"){
      const b=await body(req),a=Buffer.from(String(b.password||"")),c=Buffer.from(ADMIN_PASSWORD);
      if(a.length!==c.length||!crypto.timingSafeEqual(a,c))return send(res,401,{error:"Wrong password."});
      return send(res,200,{token:sign({role:"admin",exp:Date.now()+12*36e5})});
    }
    if(req.method==="GET"&&url==="/api/admin/orders"){if(!auth(req,"admin"))return send(res,401,{error:"Login required."});return send(res,200,{orders:db.orders.slice().reverse()})}
    if(req.method==="POST"&&url==="/api/admin/status"){
      if(!auth(req,"admin"))return send(res,401,{error:"Login required."});
      const b=await body(req),o=db.orders.find(x=>x.id===b.id);
      if(!o||!["New","Packed","Out for delivery","Delivered","Cancelled"].includes(b.status))return send(res,400,{error:"Invalid request."});
      o.status=b.status;save();return send(res,200,{ok:true});
    }
    return send(res,404,{error:"Not found"});
    }catch(e){console.error(e);return send(res,500,{error:"Server error"})}
  }
  let f=path.normalize(path.join(PUB,url==="/"?"index.html":url==="/admin"?"admin.html":url));
  if(!f.startsWith(PUB)||!fs.existsSync(f)||fs.statSync(f).isDirectory()){res.writeHead(404);return res.end("Not found")}
  res.writeHead(200,{"Content-Type":MIME[path.extname(f)]||"application/octet-stream"});fs.createReadStream(f).pipe(res);
}).listen(PORT,()=>console.log("Store running on http://localhost:"+PORT+"  |  Admin: /admin"));
