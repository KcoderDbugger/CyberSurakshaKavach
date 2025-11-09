/* app.js — Final working version with real APIs (VirusTotal + Numverify)
   Patches:
   ✅ VirusTotal waits up to 180 s
   ✅ Numverify auto-adds +91
   ✅ Clear-History button fixed
*/

/* ---------- CONFIG ---------- */
const OVERVIEW_TEXT = "Overview"; // change this text directly in code

/* ---------- tiny obfuscation helpers ---------- */
function b64Encode(s){ return btoa(unescape(encodeURIComponent(s))); }
function b64Decode(s){ return decodeURIComponent(escape(atob(s))); }
function obfEncode(raw, salt='s@1t'){
  const out=[]; for(let i=0;i<raw.length;i++) out.push(raw.charCodeAt(i)^salt.charCodeAt(i%salt.length));
  return b64Encode(String.fromCharCode(...out));
}
function obfDecode(b64,salt='s@1t'){
  try{
    const dec=b64Decode(b64);
    const arr=[...dec].map(c=>c.charCodeAt(0));
    return arr.map((v,i)=>String.fromCharCode(v^salt.charCodeAt(i%salt.length))).join('');
  }catch{ return ''; }
}

/* ---------- Embedded API Keys (obfuscated) ---------- */
const EMBED_KEYS={
  vt:'FiIAEhYjVBEQdVISEHcBFRd2CBJFdVBEFyEGEkokA0AXJgdFQ3cEF0dzAxFKcFMQEnhXEEtzU0dLcAVMQyMARA==',
  phone:'EXJSTEQhVxBHclVDEXcCFUMkB0VGcQFHSiVUR0F1A0E='
};
const EMBED_SALT='s@1t';

/* ---------- state ---------- */
const state={
  cloudConnected:true,
  history:JSON.parse(localStorage.getItem('csk_history')||'[]'),
  api:{
    vt:obfDecode(EMBED_KEYS.vt,EMBED_SALT),
    phone:obfDecode(EMBED_KEYS.phone,EMBED_SALT)
  }
};

/* ---------- utilities ---------- */
function escapeHtml(s){if(!s&&s!==0)return'';return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
function saveHistory(){try{localStorage.setItem('csk_history',JSON.stringify(state.history.slice(0,300)));}catch{} renderHistory();}
function addHistory(i){state.history.unshift({...i,time:(new Date()).toLocaleString()});saveHistory();}
function renderHistory(){
  const box=document.getElementById('history');
  if(!box)return;
  if(!state.history.length){box.innerHTML='<div class="muted">No history yet.</div>';return;}
  box.innerHTML=state.history.map(x=>`<div class="item"><div><strong>${escapeHtml(x.title)}</strong> • <small class="muted">${escapeHtml(x.time)}</small></div><div class="muted">${escapeHtml(x.detail||'')}</div><div class="tags" style="margin-top:6px"><span class="tag">${escapeHtml(x.type)}</span><span class="tag ${x.risk==='High'?'danger-text':x.risk==='Medium'?'warn-text':'ok-text'}">Risk: ${escapeHtml(x.risk)}</span></div></div>`).join('');
}

/* ---------- clear history ---------- */
function clearHistory(){
  if(!confirm('Clear all scan history?'))return;
  state.history=[];
  saveHistory();
}

/* ---------- panels ---------- */
const PANELS=[
  {id:'overview',name:'Overview',render:renderOverview},
  {id:'antivirus',name:'Antivirus',render:renderAntivirus},
  {id:'caller',name:'Caller ID',render:renderCaller}
];
function mountNav(){
  const nav=document.getElementById('nav');
  if(!nav)return;nav.innerHTML='';
  PANELS.forEach(p=>{
    const b=document.createElement('button');
    b.innerHTML=`<span>🛡️</span><div style="text-align:left"><div style="font-weight:600">${p.name}</div><small class="muted">${p.id}</small></div>`;
    b.onclick=()=>openPanel(p.id);
    b.id='nav-'+p.id;
    nav.appendChild(b);
  });
}
function setActive(id){const el=document.getElementById('activePanel');if(el)el.textContent=PANELS.find(p=>p.id===id)?.name||id;PANELS.forEach(p=>{const n=document.getElementById('nav-'+p.id);if(n)n.classList.toggle('active',p.id===id);});}
function openPanel(id){setActive(id);const p=PANELS.find(x=>x.id===id);const root=document.getElementById('panel');if(!p||!root)return;root.innerHTML='';p.render(root);window.scrollTo({top:0,behavior:'smooth'});}

/* ---------- renderers ---------- */
function renderOverview(r){
  r.innerHTML=`<div class="card"><h2>Overview</h2><div class="hr"></div><div class="muted mono" id="overviewContent">${escapeHtml(OVERVIEW_TEXT)}</div><div class="small-note">Edit Overview text inside <code>OVERVIEW_TEXT</code> in app.js</div></div>`;
}
function renderAntivirus(r){
  r.innerHTML=`<div class="card"><h2>Antivirus</h2><div class="hr"></div><input id="avInput" type="file" multiple /><button class="btn" onclick="scanFiles()">Scan</button><div class="progress"><div id="avProgress"></div></div><div id="avOut" class="log"></div><div class="small-note">Uses VirusTotal API</div></div>`;
}
function renderCaller(r){
  r.innerHTML=`<div class="card"><h2>Caller ID</h2><div class="hr"></div><input id="callNum" placeholder="Enter phone number (+91...)" /><button class="btn" onclick="lookupPhone()">Lookup</button><div id="callOut" class="log"></div><div class="small-note">Uses Numverify API</div></div>`;
}

/* ---------- VirusTotal ---------- */
async function scanFiles(){
  const files=[...(document.getElementById('avInput').files||[])];
  if(!files.length){alert('Select files');return;}
  const out=document.getElementById('avOut');out.innerHTML='';
  const prog=document.getElementById('avProgress');prog.style.width='0%';
  const vtKey=state.api.vt;

  for(let i=0;i<files.length;i++){
    const f=files[i];
    const item=document.createElement('div');
    item.className='item';
    item.innerHTML=`<div><strong>${escapeHtml(f.name)}</strong></div><div class="muted">Uploading to VirusTotal…</div>`;
    out.appendChild(item);

    try{
      const form=new FormData();form.append('file',f);
      const up=await fetch('https://www.virustotal.com/api/v3/files',{method:'POST',headers:{'x-apikey':vtKey},body:form});
      const upJson=await up.json();
      const analysisId=upJson.data?.id;
      let result=null;

      // wait up to 180 s (60 × 3 s)
      for(let j=0;j<60;j++){
        await sleep(3000);
        const a=await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`,{headers:{'x-apikey':vtKey}});
        const aj=await a.json();
        if(aj.data?.attributes?.status==='completed'){result=aj.data.attributes.stats;break;}
      }

      if(result){
        const mal=result.malicious>0;
        item.innerHTML=`<div><strong>${escapeHtml(f.name)}</strong></div>
          <div class="${mal?'danger-text':'ok-text'}">${mal?'Malicious':'Clean'}</div>
          <div class="small muted">Malicious:${result.malicious} • Suspicious:${result.suspicious}</div>`;
        addHistory({title:'Antivirus Scan',type:'Antivirus',risk:mal?'High':'Low',detail:`${f.name} • Mal:${result.malicious}`});
      }else{
        item.innerHTML=`<div><strong>${escapeHtml(f.name)}</strong></div><div class="warn-text">Pending or not analyzed</div>`;
      }
    }catch(e){
      console.error(e);
      item.innerHTML=`<div><strong>${escapeHtml(f.name)}</strong></div><div class="warn-text">Error uploading to VT</div>`;
    }
    prog.style.width=Math.min(100,Math.round(((i+1)/files.length)*100))+'%';
  }
}

/* ---------- Numverify ---------- */
async function lookupPhone(){
  let num=(document.getElementById('callNum').value||'').trim();
  if(!num){alert('Enter phone');return;}

  // auto-add +91 if user typed 10 digits without prefix
  if(/^\d{10}$/.test(num)) num='+91'+num;

  const out=document.getElementById('callOut');out.innerHTML='Looking up...';
  const key=state.api.phone;

  try{
    const res=await fetch(`https://apilayer.net/api/validate?access_key=${encodeURIComponent(key)}&number=${encodeURIComponent(num)}`);
    const js=await res.json();
    if(js.valid){
      out.innerHTML=`<div class="ok-text">Valid Number</div>
        <div class="small muted">Country: ${js.country_code||'Unknown'} • Carrier: ${js.carrier||'Unknown'}</div>`;
      addHistory({title:'Caller Lookup',type:'Call',risk:'Low',detail:`${num} • ${js.country_code}`});
    }else{
      out.innerHTML=`<div class="warn-text">Invalid or risky number</div>`;
      addHistory({title:'Caller Lookup',type:'Call',risk:'Medium',detail:`${num} invalid`});
    }
  }catch(e){
    console.error(e);
    out.innerHTML=`<div class="warn-text">Error contacting Numverify</div>`;
  }
}

/* ---------- Gmail Report ---------- */
function finalizeReportAndOpenMail(type,meta){
  const to='kdivyamsingh@gmail.com';
  const subject=encodeURIComponent(`[CSK AI Report] ${type}`);
  const body=encodeURIComponent(JSON.stringify(meta,null,2));
  window.open(`https://mail.google.com/mail/?view=cm&fs=1&to=${to}&su=${subject}&body=${body}`,'_blank');
}

/* ---------- init ---------- */
function init(){
  mountNav();
  openPanel('overview');
  renderHistory();
  const clr=document.querySelector('.btn.warn');
  if(clr) clr.addEventListener('click',clearHistory);
}
init();
