// Attendance server. Zero dependencies: only Node.js (v16+) is needed.
'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib');
const ROOT=__dirname, DATA=path.join(ROOT,'data');
fs.mkdirSync(DATA,{recursive:true});
const CFG_PATH=path.join(ROOT,'config.json');
let cfg={port:3000,masterPassword:''};
try{cfg=Object.assign(cfg,JSON.parse(fs.readFileSync(CFG_PATH,'utf8')))}catch(e){}
if(!cfg.masterPassword){
  cfg.masterPassword=String(crypto.randomInt(100000,999999));
  fs.writeFileSync(CFG_PATH,JSON.stringify(cfg,null,2));
  console.log('\n*** MASTER PASSWORD: '+cfg.masterPassword+'  (saved in config.json) ***\n');
}
const BASE=JSON.parse(fs.readFileSync(path.join(ROOT,'people.json'),'utf8'));
const STATE_PATH=path.join(DATA,'state.json'), LOG_PATH=path.join(DATA,'log.jsonl');
let S={att:{},extra:{},ops:{},sessions:{}};
try{S=Object.assign(S,JSON.parse(fs.readFileSync(STATE_PATH,'utf8')))}catch(e){}
function save(){const t=STATE_PATH+'.tmp';fs.writeFileSync(t,JSON.stringify(S));fs.renameSync(t,STATE_PATH)}
function log(o){try{fs.appendFileSync(LOG_PATH,JSON.stringify(Object.assign({t:Date.now()},o))+'\n')}catch(e){}}
const rid=()=>crypto.randomBytes(6).toString('hex');
const hashPin=(pin,salt)=>crypto.scryptSync(String(pin),salt,32).toString('hex');
const eq=(a,b)=>{const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y)};

/* ---- realtime (Server-Sent Events) ---- */
const conns=new Map(); // cid -> {res,opId,token,last}
function broadcast(ev,data){const m=`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`;for(const c of conns.values()){try{c.res.write(m)}catch(e){}}}
function presenceMap(){const m={};for(const id in S.ops)m[id]={online:0,last:S.ops[id].lastSeen||0};for(const c of conns.values())if(m[c.opId])m[c.opId].online++;return m}
function pushPresence(){broadcast('presence',presenceMap())}
function dropConn(cid,end){
  const c=conns.get(cid);if(!c)return;conns.delete(cid);
  if(end){try{c.res.end()}catch(e){}}
  if(S.ops[c.opId]){S.ops[c.opId].lastSeen=Date.now();try{save()}catch(e){}}
  pushPresence();
}
function dropWhere(fn){for(const [cid,c] of [...conns])if(fn(c))dropConn(cid,true)}
setInterval(()=>{broadcast('hb',{t:Date.now()})},15000);
setInterval(()=>{const now=Date.now();for(const [cid,c] of [...conns])if(now-c.last>45000)dropConn(cid,true)},10000);
const fails=new Map(); // login brute-force limiter

/* ---- helpers ---- */
const allPeople=()=>BASE.concat(Object.entries(S.extra).map(([id,m])=>({id,last:m.last,first:m.first,name:(m.last+' '+m.first).trim(),father:m.father,phone:m.phone,alias:m.alias,extra:true,by:m.by,at:m.at})));
const opsPublic=()=>Object.entries(S.ops).map(([id,o])=>({id,name:o.name,at:o.at,role:o.role||'admin'}));
function auth(req,url){
  const h=req.headers.authorization||'';
  const t=h.startsWith('Bearer ')?h.slice(7):url.searchParams.get('token');
  const opId=t&&S.sessions[t];
  if(!opId||!S.ops[opId])return null;
  return {token:t,opId,name:S.ops[opId].name,role:S.ops[opId].role||'admin'};
}
function body(req){return new Promise((res,rej)=>{let b='';req.on('data',c=>{b+=c;if(b.length>1e6){req.destroy();rej(new Error('big'))}});req.on('end',()=>{try{res(b?JSON.parse(b):{})}catch(e){rej(e)}});})}
function send(res,code,obj,extra){res.writeHead(code,Object.assign({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'},extra||{}));res.end(JSON.stringify(obj))}
const normDigits=s=>String(s||'').replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d));

/* ---- minimal XLSX writer (zip + XML, no libraries) ---- */
const CRC=(()=>{const t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;t[n]=c>>>0}return t})();
const crc32=b=>{let c=0xFFFFFFFF;for(let i=0;i<b.length;i++)c=CRC[(c^b[i])&255]^(c>>>8);return (c^0xFFFFFFFF)>>>0};
function zip(files){
  const parts=[],cd=[];let off=0;
  for(const [name,content] of files){
    const nm=Buffer.from(name),raw=Buffer.from(content,'utf8'),def=zlib.deflateRawSync(raw),crc=crc32(raw);
    const lh=Buffer.alloc(30);lh.writeUInt32LE(0x04034b50,0);lh.writeUInt16LE(20,4);lh.writeUInt16LE(0x0800,6);lh.writeUInt16LE(8,8);lh.writeUInt32LE(0,10);lh.writeUInt32LE(crc,14);lh.writeUInt32LE(def.length,18);lh.writeUInt32LE(raw.length,22);lh.writeUInt16LE(nm.length,26);
    parts.push(lh,nm,def);
    const ch=Buffer.alloc(46);ch.writeUInt32LE(0x02014b50,0);ch.writeUInt16LE(20,4);ch.writeUInt16LE(20,6);ch.writeUInt16LE(0x0800,8);ch.writeUInt16LE(8,10);ch.writeUInt32LE(crc,16);ch.writeUInt32LE(def.length,20);ch.writeUInt32LE(raw.length,24);ch.writeUInt16LE(nm.length,28);ch.writeUInt32LE(off,42);
    cd.push(ch,nm);off+=30+nm.length+def.length;
  }
  const cdb=Buffer.concat(cd),e=Buffer.alloc(22);e.writeUInt32LE(0x06054b50,0);e.writeUInt16LE(files.length,8);e.writeUInt16LE(files.length,10);e.writeUInt32LE(cdb.length,12);e.writeUInt32LE(off,16);
  return Buffer.concat(parts.concat([cdb,e]));
}
const xe=s=>String(s==null?'':s).replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c])).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g,'');
const colName=i=>String.fromCharCode(65+i);
function sheetXml(rows,widths){
  let x='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView rightToLeft="1" workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>'+widths.map((w,i)=>`<col min="${i+1}" max="${i+1}" width="${w}" customWidth="1"/>`).join('')+'</cols><sheetData>';
  rows.forEach((r,ri)=>{x+=`<row r="${ri+1}">`+r.map((v,ci)=>{
    const ref=colName(ci)+(ri+1),st=ri===0?' s="1"':'';
    if(typeof v==='number')return `<c r="${ref}"${st}><v>${v}</v></c>`;
    return `<c r="${ref}"${st} t="inlineStr"><is><t xml:space="preserve">${xe(v)}</t></is></c>`;
  }).join('')+'</row>'});
  return x+'</sheetData></worksheet>';
}
function buildXlsx(){
  const fmt=ms=>{try{return new Date(ms).toLocaleString('fa-IR',{dateStyle:'short',timeStyle:'short',timeZone:'Asia/Tehran'})}catch(e){return new Date(ms).toISOString()}};
  const head=['ردیف','نام و نام خانوادگی','نام پدر','شماره تماس','اسم مستعار','وضعیت','زمان حضور','ثبت‌کننده حضور','تاییدکننده نهایی','زمان تایید','اضافه‌شده توسط'];
  const ppl=allPeople();
  const rows=[head];
  ppl.forEach((p,i)=>{const a=S.att[p.id];rows.push([i+1,p.name,p.father||'',p.phone||'',p.alias||'',a?(a.conf?'حاضر (تایید شده)':'منتظر تایید'):'غایب',a?fmt(a.at):'',a?a.by:'',a&&a.conf?a.conf.by:'',a&&a.conf?fmt(a.conf.at):'',p.extra?p.by:'']);});
  const here=[head].concat(rows.slice(1).filter(r=>r[5]==='حاضر (تایید شده)'));
  const per={};Object.values(S.att).forEach(a=>{per[a.by]=(per[a.by]||0)+1});
  const stat=[['ثبت‌کننده','تعداد حضور ثبت‌شده']].concat(Object.entries(per).sort((a,b)=>b[1]-a[1]));
  const W=[6,30,16,14,14,16,18,16,16,18,16];
  const names=['همه افراد','تایید شده‌ها','آمار ادمین‌ها'];
  const files=[
   ['[Content_Types].xml','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'+[1,2,3].map(i=>`<Override PartName="/xl/worksheets/sheet${i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('')+'</Types>'],
   ['_rels/.rels','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'],
   ['xl/workbook.xml','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView/></bookViews><sheets>'+names.map((n,i)=>`<sheet name="${xe(n)}" sheetId="${i+1}" r:id="rId${i+1}"/>`).join('')+'</sheets></workbook>'],
   ['xl/_rels/workbook.xml.rels','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'+[1,2,3].map(i=>`<Relationship Id="rId${i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i}.xml"/>`).join('')+'<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'],
   ['xl/styles.xml','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>'],
   ['xl/worksheets/sheet1.xml',sheetXml(rows,W)],['xl/worksheets/sheet2.xml',sheetXml(here,W)],['xl/worksheets/sheet3.xml',sheetXml(stat,[22,18])]
  ];
  return zip(files);
}

/* ---- routes ---- */
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.ico':'image/x-icon'};
const server=http.createServer(async(req,res)=>{
  try{
    const url=new URL(req.url,'http://x');const p=url.pathname;
    if(!p.startsWith('/api/')){
      const f=path.join(ROOT,'public',p==='/'?'index.html':path.normalize(p).replace(/^(\.\.[\/\\])+/,''));
      if(!f.startsWith(path.join(ROOT,'public'))||!fs.existsSync(f)||fs.statSync(f).isDirectory()){res.writeHead(404);return res.end('not found')}
      res.writeHead(200,{'Content-Type':MIME[path.extname(f)]||'application/octet-stream','Cache-Control':'no-cache'});return fs.createReadStream(f).pipe(res);
    }
    if(p==='/api/ops'&&req.method==='GET')return send(res,200,{ops:opsPublic().map(o=>({id:o.id,name:o.name,role:o.role}))});
    if(p==='/api/login'&&req.method==='POST'){
      const b=await body(req),o=S.ops[b.opId];
      const key=(req.socket.remoteAddress||'')+'|'+b.opId,f=fails.get(key)||{n:0,until:0};
      if(f.until>Date.now())return send(res,429,{error:'تلاش‌های ناموفق زیاد بود. یک دقیقه صبر کنید.'});
      if(!o||!eq(hashPin(normDigits(b.pin),o.salt),o.hash)){f.n++;if(f.n>=5){f.until=Date.now()+60000;f.n=0}fails.set(key,f);return send(res,401,{error:'پین اشتباه است'})}
      fails.delete(key);
      const t=crypto.randomBytes(24).toString('hex');S.sessions[t]=b.opId;save();
      return send(res,200,{token:t,op:{id:b.opId,name:o.name,role:o.role||'admin'}});
    }
    // master-password routes (manage admins)
    if(p==='/api/ops'&&req.method==='POST'){
      const b=await body(req);if(!eq(b.master||'',cfg.masterPassword))return send(res,403,{error:'رمز مدیر اشتباه است'});
      const name=String(b.name||'').trim(),pin=normDigits(b.pin);
      if(!name||!/^\d{4,8}$/.test(pin))return send(res,400,{error:'نام و پین ۴ تا ۸ رقمی لازم است'});
      const old=Object.entries(S.ops).find(([,o])=>o.name===name);
      const id=old?old[0]:rid(),salt=crypto.randomBytes(8).toString('hex');
      S.ops[id]={name,salt,hash:hashPin(pin,salt),at:old?old[1].at:Date.now(),role:b.role==='manager'?'manager':'admin'};save();log({ev:'op-set',name,role:S.ops[id].role});
      broadcast('ops',{});pushPresence();return send(res,200,{ok:true});
    }
    if(p.startsWith('/api/ops/')&&req.method==='DELETE'){
      if(!eq(req.headers['x-master']||'',cfg.masterPassword))return send(res,403,{error:'رمز مدیر اشتباه است'});
      const id=p.split('/').pop();dropWhere(c=>c.opId===id);delete S.ops[id];for(const t in S.sessions)if(S.sessions[t]===id)delete S.sessions[t];save();log({ev:'op-del',id});
      broadcast('ops',{});return send(res,200,{ok:true});
    }
    const me=auth(req,url);
    if(!me)return send(res,401,{error:'ورود لازم است'});
    if(p==='/api/events'){
      res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'});
      res.write('retry: 2000\n\n');
      const cid=(url.searchParams.get('cid')||rid()).slice(0,40);
      if(conns.has(cid))dropConn(cid,true);
      conns.set(cid,{res,opId:me.opId,token:me.token,last:Date.now()});
      req.on('close',()=>{const c=conns.get(cid);if(c&&c.res===res)dropConn(cid,false)});
      pushPresence();return;
    }
    if(p==='/api/ping'&&req.method==='POST'){
      const b=await body(req),c=conns.get(String(b.cid||''));
      if(c&&c.token===me.token){c.last=Date.now();return send(res,200,{ok:true,t:Date.now()})}
      return send(res,200,{ok:true,reconnect:true,t:Date.now()});
    }
    if(p==='/api/logout'&&req.method==='POST'){
      dropWhere(c=>c.token===me.token);delete S.sessions[me.token];save();return send(res,200,{ok:true});
    }
    if(p==='/api/state')return send(res,200,{me:{id:me.opId,name:me.name,role:me.role},people:allPeople(),att:S.att,ops:opsPublic(),presence:presenceMap()});
    if(p==='/api/mark'&&req.method==='POST'){
      const b=await body(req);
      if(!allPeople().some(x=>x.id===b.pid))return send(res,404,{error:'فرد پیدا نشد'});
      if(S.att[b.pid])return send(res,409,{error:'قبلاً توسط '+S.att[b.pid].by+' ثبت شده',rec:S.att[b.pid]});
      const rec={by:me.name,opId:me.opId,at:Date.now()};if(me.role==='manager')rec.conf={by:me.name,at:rec.at};S.att[b.pid]=rec;save();log({ev:'mark',pid:b.pid,by:me.name});
      broadcast('att',{pid:b.pid,rec});return send(res,200,{ok:true,rec});
    }
    if(p==='/api/unmark'&&req.method==='POST'){
      const b=await body(req);if(S.att[b.pid]&&S.att[b.pid].conf&&me.role!=='manager')return send(res,403,{error:'حضور تاییدشده را فقط مدیر کل می‌تواند لغو کند'});
      if(S.att[b.pid]){delete S.att[b.pid];save();log({ev:'unmark',pid:b.pid,by:me.name});broadcast('att',{pid:b.pid,rec:null})}
      return send(res,200,{ok:true});
    }
    if(p==='/api/confirm'&&req.method==='POST'){
      if(me.role!=='manager')return send(res,403,{error:'تایید نهایی فقط با حساب مدیر کل ممکن است'});
      const b=await body(req);const pids=Array.isArray(b.pids)?b.pids:[b.pid];let n=0;
      for(const pid of pids){const r=S.att[pid];if(r&&!r.conf){r.conf={by:me.name,at:Date.now()};n++;log({ev:'confirm',pid,by:me.name});broadcast('att',{pid,rec:r})}}
      if(n)save();return send(res,200,{ok:true,n});
    }
    if(p==='/api/unconfirm'&&req.method==='POST'){
      if(me.role!=='manager')return send(res,403,{error:'فقط مدیر کل'});
      const b=await body(req),r=S.att[b.pid];if(r&&r.conf){delete r.conf;save();log({ev:'unconfirm',pid:b.pid,by:me.name});broadcast('att',{pid:b.pid,rec:r})}
      return send(res,200,{ok:true});
    }
    if(p==='/api/people'&&req.method==='POST'){
      const b=await body(req);const t=k=>String(b[k]||'').trim().slice(0,80);
      let ph=normDigits(t('phone')).replace(/\D/g,'');if(ph.length===10&&ph[0]==='9')ph='0'+ph;
      if(!t('first')||!t('last')||!t('father')||!/^09\d{9}$/.test(ph))return send(res,400,{error:'اطلاعات ناقص یا شماره نامعتبر است'});
      const id='e'+rid();const m={first:t('first'),last:t('last'),father:t('father'),phone:ph,alias:t('alias'),by:me.name,at:Date.now()};
      S.extra[id]=m;let rec=null;if(b.markNow){rec={by:me.name,opId:me.opId,at:Date.now()};if(me.role==='manager')rec.conf={by:me.name,at:rec.at};S.att[id]=rec}
      save();log({ev:'add',id,by:me.name});
      const person={id,last:m.last,first:m.first,name:(m.last+' '+m.first).trim(),father:m.father,phone:m.phone,alias:m.alias,extra:true,by:m.by,at:m.at};
      broadcast('person',{person,rec});return send(res,200,{ok:true,id});
    }
    if(p==='/api/export.xlsx'){
      const buf=buildXlsx();
      res.writeHead(200,{'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':'attachment; filename="attendance-'+new Date().toISOString().slice(0,10)+'.xlsx"','Content-Length':buf.length});return res.end(buf);
    }
    send(res,404,{error:'نامعتبر'});
  }catch(e){console.error(e);try{send(res,500,{error:'خطای سرور'})}catch(_){}}
});
server.listen(cfg.port,'0.0.0.0',()=>console.log('Server running: http://localhost:'+cfg.port));
