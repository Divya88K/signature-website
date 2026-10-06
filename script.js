"use strict";
const $=id=>document.getElementById(id);
const PSS={name:"RSA-PSS",saltLength:32};
const KEYALG={name:"RSA-PSS",hash:"SHA-256"};
const EXT=["txt","md","pdf","docx","png","jpg","jpeg"], MAX=5*1024*1024;
const MAGIC={pdf:[0x25,0x50,0x44,0x46],png:[0x89,0x50,0x4E,0x47],jpg:[0xFF,0xD8,0xFF],jpeg:[0xFF,0xD8,0xFF],docx:[0x50,0x4B]};
let pair=null, pubPem="", lastSig=null;

/* ---------- helpers ---------- */
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const sha=async d=>hex(await crypto.subtle.digest("SHA-256",d));
const toPem=b=>"-----BEGIN PUBLIC KEY-----\n"+btoa(String.fromCharCode(...new Uint8Array(b))).match(/.{1,64}/g).join("\n")+"\n-----END PUBLIC KEY-----\n";
function fromPem(t){const m=t.match(/-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/);
 if(!m) throw new Error("This is not a valid public key (.pem) file.");
 return Uint8Array.from(atob(m[1].replace(/\s+/g,"")),c=>c.charCodeAt(0));}
function say(el,text,kind){el.textContent=text;el.className="msg "+kind;el.hidden=false;}
function verdict(el,ok,text){el.className="result "+(ok?"valid":"invalid");el.textContent=(ok?"✔ VALID":"✘ INVALID");
 const s=document.createElement("small");s.textContent=text;el.appendChild(s);el.hidden=false;}
function save(bytes,name,type){const u=URL.createObjectURL(new Blob([bytes],{type}));const a=document.createElement("a");
 a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u);}
async function readFile(input,label,allowed,max){
 const f=input.files[0]; if(!f) throw new Error(label+": please choose a file.");
 const ext=(f.name.split(".").pop()||"").toLowerCase();
 if(!allowed.includes(ext)) throw new Error(label+": file type not allowed ("+allowed.join(", ")+").");
 if(f.size===0) throw new Error(label+": file is empty.");
 if(f.size>max) throw new Error(label+": file is too large (limit "+Math.round(max/1024)+" KB).");
 const data=new Uint8Array(await f.arrayBuffer());
 const m=MAGIC[ext]; if(m&&!m.every((b,i)=>data[i]===b)) throw new Error(label+": content does not match the ."+ext+" extension.");
 return data;}
async function busy(btn,fn){btn.disabled=true;try{await fn();}finally{btn.disabled=false;}}
async function ensureKey(){ if(pair) return;
 pair=await crypto.subtle.generateKey({...KEYALG,modulusLength:2048,publicExponent:new Uint8Array([1,0,1])},false,["sign","verify"]);
 const spki=await crypto.subtle.exportKey("spki",pair.publicKey);
 pubPem=toPem(spki); $("pem").value=pubPem; $("fp").textContent=await sha(spki); $("keyInfo").hidden=false;}

/* ---------- navigation ---------- */
function go(p){document.querySelectorAll("main>section").forEach(s=>s.classList.toggle("on",s.id===p));
 document.querySelectorAll("nav button").forEach(b=>b.classList.toggle("on",b.dataset.p===p));
 try{history.replaceState(null,"","#"+p);}catch(e){} window.scrollTo(0,0);}
document.querySelectorAll("[data-p]").forEach(b=>b.onclick=()=>go(b.dataset.p));
document.querySelectorAll("[data-go]").forEach(b=>b.onclick=()=>go(b.dataset.go));
go(["home","keys","sign","verify"].includes(location.hash.slice(1))?location.hash.slice(1):"home");

if(!(window.crypto&&crypto.subtle)){document.querySelector("main").prepend(Object.assign(document.createElement("div"),
 {className:"msg err",textContent:"This browser does not support Web Crypto (or the page is not on HTTPS). Use a current Chrome, Edge, Firefox or Safari."}));}

/* ---------- keys ---------- */
$("genBtn").onclick=()=>busy($("genBtn"),async()=>{try{
 if(pair&&!confirm("Replace the current key pair? The old private key will be lost.")) return;
 pair=null; await ensureKey();
 say($("keyMsg"),"RSA-2048 key pair created. The private key is non-extractable and never leaves this browser.","ok");
 }catch(e){say($("keyMsg"),"Key generation failed: "+e.message,"err");}});
$("dlPub").onclick=()=>save(pubPem,"public_key.pem","application/x-pem-file");

/* ---------- sign ---------- */
$("signBtn").onclick=()=>busy($("signBtn"),async()=>{try{
 if(!pair) throw new Error("Generate a key pair first (Keys page).");
 const data=await readFile($("signFile"),"Document",EXT,MAX);
 lastSig=new Uint8Array(await crypto.subtle.sign(PSS,pair.privateKey,data));
 say($("signMsg"),"Document signed with RSA-PSS (SHA-256). Signature size: "+lastSig.length+" bytes.","ok");
 $("signHash").textContent="Document SHA-256: "+await sha(data);$("signHash").hidden=false;$("dlSig").hidden=false;
 }catch(e){say($("signMsg"),e.message,"err");}});
$("dlSig").onclick=()=>{if(lastSig) save(lastSig,"document.sig","application/octet-stream");};

/* ---------- verify ---------- */
$("verBtn").onclick=()=>busy($("verBtn"),async()=>{$("verRes").hidden=true;$("verMsg").hidden=true;try{
 const data=await readFile($("vDoc"),"Document",EXT,MAX);
 const sig=await readFile($("vSig"),"Signature",["sig"],1024);
 let key;
 if($("vKey").files[0]){const k=await readFile($("vKey"),"Public key",["pem"],10*1024);
  key=await crypto.subtle.importKey("spki",fromPem(new TextDecoder().decode(k)),KEYALG,false,["verify"]);}
 else if(pair) key=pair.publicKey;
 else throw new Error("Upload a public key (.pem) or generate a key pair first.");
 const ok=await crypto.subtle.verify(PSS,key,sig,data);
 verdict($("verRes"),ok,ok?"Signature is authentic and the document has not been modified."
  :"The document was modified, the signature is damaged, or a different key was used.");
 $("verHash").textContent="Document SHA-256: "+await sha(data);$("verHash").hidden=false;
 }catch(e){say($("verMsg"),e.message,"err");}});

