"""Threat Intelligence tab of report.html (shared by the Windows / Linux / macOS report
builders). The page reads D.threat_intel = <case>/threat_intelligence/ti_report.json."""

TI_PAGE_JS = r"""
function tiPill(v){v=String(v||'');const c={HIGH:'red',MEDIUM:'amber',LOW:'blue',malicious:'red',suspicious:'amber',
 clean:'green','not on VirusTotal':'blue',complete:'green',partial:'amber',rebuilt:'purple',region:'purple',empty:'',
 odd:'amber',system:'green','not checked':'',stale:'red'}[v];return `<span class="pill ${c||''}">${esc(v)}</span>`}
function tiTable(rs,id,cols,limit){limit=limit||2500;if(!rs||!rs.length)return'<div class="empty">Nothing to show.</div>';
 cols=cols.filter(c=>rs.some(r=>{const v=c[1](r);return v!=null&&String(v)!==''}));  /* a column empty in every row says nothing */
 let h=`<input class="search" placeholder="Search this table..." oninput="filterTable('${id}',this.value)"><div class="tablewrap"><table id="${id}"><thead><tr>`;
 cols.forEach((c,i)=>h+=`<th onclick="sortTable('${id}',${i})">${esc(c[0])}</th>`);h+='</tr></thead><tbody>';
 rs.slice(0,limit).forEach(r=>{h+='<tr>';cols.forEach(c=>{const v=c[1](r);h+=`<td class="${c[2]||'wrap'}">${v==null?'':v}</td>`});h+='</tr>'});
 h+='</tbody></table></div>';if(rs.length>limit)h+=`<div class="note">Showing ${limit} of ${rs.length} rows. <button class="btn" onclick="tiShowAll('${id}')">Show all ${rs.length}</button></div>`;
 return h}
const TI_FULL={};
function tiShowAll(id){const f=TI_FULL[id];if(!f)return;const box=document.getElementById(id).closest('.tisec');box.innerHTML=f.title+tiTable(f.rows,id,f.cols,1e9)}
function tiSec(title,id,rows,cols,limit,intro){TI_FULL[id]={rows:rows,cols:cols,title:`<h2>${title}</h2>`+(intro||'')};
 return `<div class="card tisec"><h2>${title}</h2>${intro||''}${tiTable(rows,id,cols,limit)}</div>`}
function tiLink(u,t){return u&&/^https?:\/\//i.test(String(u))?`<a style="color:#60a5fa" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t||u)}</a>`:''}
function pageThreatIntel(el){
 const T=D.threat_intel;
 if(!T||!T.generated){el.innerHTML='<div class="card"><h2>Threat Intelligence</h2><div class="empty">Threat intel was not run for this case. '
  +'Use the preset <b>DFIR + Threat Intel</b>, or <b>Case &rsaquo; Threat intel on this case</b> in RAMBreaker '
  +'(command line: <code>rambreaker-cli.cmd ti -o &lt;case&gt;</code>).</div></div>';return}
 const vt=T.vt||{},vv=T.vt_verdicts||{},ys=T.yara_by_severity||{},fs=T.feed_by_confidence||{},hq=T.hash_quality||{};
 let h='<div class="card"><h2>Threat Intelligence</h2>'+sourceTag('threat intel','threat_intelligence/ti_report.json')
  +'<p class="note">Every file and every process executable recoverable from this memory image was dumped and hashed; '
  +'the memory regions flagged by the injection correlator were dumped too (fileless code never exists as a file). '
  +'Each object was then checked <b>on this PC</b> with YARA rules and offline threat feeds. Only the short list below '
  +'went to VirusTotal, and only as hashes, public IP addresses and domain names. No file was uploaded.</p>'
  +'<div class="grid">'
  +`<div class="stat"><div class="n">${esc(T.objects||0)}</div><div class="l">Objects dumped + hashed</div></div>`
  +`<div class="stat"><div class="n">${esc(ys.HIGH||0)} / ${esc(ys.MEDIUM||0)} / ${esc(ys.LOW||0)}</div><div class="l">YARA hits HIGH / MED / LOW</div></div>`
  +`<div class="stat"><div class="n">${esc(fs.HIGH||0)} / ${esc(fs.MEDIUM||0)} / ${esc(fs.LOW||0)}</div><div class="l">Feed hits HIGH / MED / LOW</div></div>`
  +`<div class="stat"><div class="n">${vt.enabled?esc((vv.malicious||0)+' / '+(vv.suspicious||0)):'off'}</div><div class="l">VirusTotal malicious / suspicious</div></div>`
  +`<div class="stat"><div class="n">${esc(T.shortlist_total||0)}</div><div class="l">On the "look here first" list</div></div></div>`;
 h+=`<p class="note">Generated ${esc(T.generated)} in ${esc(Math.round(T.duration_s||0))} s. Hash quality: `
  +Object.entries(hq).map(([k,v])=>`${tiPill(k)} ${esc(v)}`).join(' ')+'. <b>complete</b> = the hash should match the original file; '
  +'<b>partial</b> = pages were not in RAM; <b>rebuilt</b> = reassembled from memory (VirusTotal will rarely know it, YARA still works).</p>';
 const stale=(T.stale||[]),nd=(T.not_downloaded||[]),rm=(T.removed_after_download||[]);
 if(rm.length)h+='<div class="note" style="border-left:3px solid #ef4444;padding-left:10px">'
  +`<b>Missing after download:</b> ${esc(rm.join(', '))}. These databases were downloaded to this PC, but the files are gone, `
  +'so they were <b>not checked</b> in this run. Antivirus software often removes threat-intel lists because they contain malware addresses and hashes. '
  +'To use them, add an antivirus exclusion for the <b>threat_intel_db</b> folder next to RAMBreaker (steps: DEFENDER.md), download them again '
  +'(<b>Settings &rsaquo; Threat-intel databases</b>) and re-run this step.</div>';
 if(stale.length||nd.length)h+='<div class="note" style="border-left:3px solid #f59e0b;padding-left:10px">'
  +(stale.length?`<b>Out of date:</b> ${esc(stale.join(', '))} (older than 7 days). `:'')
  +(nd.length?`<b>Not downloaded:</b> ${esc(nd.join(', '))}. `:'')
  +'Threat intelligence changes every day: new malware, new C2 servers. Update the databases in RAMBreaker '
  +'(<b>Settings &rsaquo; Threat-intel databases</b>) when you have internet access, then re-run this step. Updating is your choice.</div>';
 if(vt.stopped)h+=`<div class="note"><b>VirusTotal:</b> ${esc(vt.stopped)}</div>`;
 (T.notes||[]).forEach(n=>h+=`<div class="note">${esc(n)}</div>`);
 h+='</div>';
 const S=T.shortlist||[];
 const noVT=c=>vt.enabled||c[0]!=='VirusTotal';
 h+=tiSec('Look here first','tiShort',S,[
  ['Score',r=>`<b>${esc(r.score)}</b>`,'nw'],['Type',r=>esc(r.type),'nw'],
  ['Object',r=>esc(r.name)+(r.path&&r.path!==r.name?`<div class="dim">${esc(r.path)}</div>`:'')],
  ['Process',r=>r.pid?esc((r.process||'')+' (PID '+r.pid+')'):'','nw'],
  ['Why',r=>(r.reasons||[]).map(x=>esc(x.text)).join('<br>')],
  ['Hash quality',r=>r.quality?tiPill(r.quality):'','nw'],
  ['VirusTotal',r=>r.vt?tiPill(r.vt.verdict)+(r.vt.found?` ${esc(r.vt.malicious)}/${esc(r.vt.total)} `:' ')+tiLink(r.vt.link,'open'):'','nw'],
  ['SHA-256',r=>esc(r.sha256||''),'nw']].filter(noVT),300,
  '<p class="note">Objects with at least one reason to look, highest score first. Points: own YARA rule / high-score rule or a hash on a feed = high; '
  +'a feed hit on a live network connection = high; IPs and domains that only appear as strings in memory are often blocklists or browser data: they are low and, with no other reason, listed only under Feed hits. '
  +'A VirusTotal "malicious" verdict sets the score to 100.</p>');
 h+=tiSec('YARA matches','tiYara',T.yara_hits||[],[
  ['Severity',r=>tiPill(r.severity),'nw'],['Rule',r=>`<b>${esc(r.rule)}</b>`+(r.tags&&r.tags.length?`<div class="dim">${esc(r.tags.join(', '))}</div>`:'')],
  ['Rule set',r=>esc(r.namespace),'nw'],['Score',r=>esc(r.score==null?'':r.score),'nw'],
  ['Object',r=>esc(r.object)+(r.path?`<div class="dim">${esc(r.path)}</div>`:'')],
  ['Process',r=>r.pid?esc((r.process||'')+' ('+r.pid+')'):'','nw'],
  ['Description',r=>esc(r.description)+(r.note?`<div class="dim">${esc(r.note)}</div>`:'')+(r.reference?'<div>'+tiLink(String(r.reference).split(/[ ,]/)[0],'reference')+'</div>':'')],
  ['Matched',r=>(r.strings||[]).slice(0,4).map(s=>`<code>${esc(s.id)}@${esc(s.offset)}: ${esc(s.text)}</code>`).join('<br>')],
  ['Dumped file',r=>esc(r.file),'nw']],1500,
  `<p class="note">${esc((T.yara||{}).rules||0)} rules from ${esc(((T.yara||{}).files||[]).map(f=>f.namespace+' ('+f.rules+', '+f.modified+')').join(', '))}`
  +`; ${esc((T.yara||{}).scanned||0)} objects scanned in ${esc((T.yara||{}).seconds||0)} s.`
  +(((T.yara||{}).skipped||[]).length?` Skipped rule files (errors): ${esc(T.yara.skipped.map(s=>s.file).join(', '))}.`:'')
  +' Severity: your own custom rules = HIGH; YARA Forge score 80+ = HIGH, 60-79 = MEDIUM, lower = LOW.</p>');
 h+=tiSec('Offline threat-feed hits','tiFeed',T.feed_hits||[],[
  ['Confidence',r=>tiPill(r.confidence),'nw'],['Kind',r=>esc(r.kind),'nw'],['Indicator',r=>`<b>${esc(r.value)}</b>`],
  ['Feed',r=>esc(r.source_name)],['Listed as',r=>esc(r.label)+(r.listed_as?`<div class="dim">${esc(r.listed_as)}</div>`:'')],
  ['Found in this image',r=>(r.found_in||[]).map(esc).join('<br>')+(r.note?`<div class="dim">${esc(r.note)}</div>`:'')]],1500,
  '<p class="note">Hashes, network connections, browser history and the IPs/domains/URLs already extracted from memory, compared with the local feeds. '
  +'HIGH = a hash, or an indicator seen in a live connection or browser history; LOW = only a string somewhere in RAM.</p>');
 h+=tiSec('VirusTotal','tiVT',T.vt_results||[],[
  ['Kind',r=>esc(r.kind),'nw'],['Looked up',r=>esc(r.id),'nw'],['Object',r=>esc(r.object)],
  ['Result',r=>r.state==='checked'?tiPill(r.verdict):tiPill(r.state),'nw'],
  ['Detections',r=>r.found?esc(r.malicious+' malicious, '+r.suspicious+' suspicious of '+r.total):'','nw'],
  ['Label',r=>esc(r.label||r.meaningful_name||'')],['Detail',r=>esc(r.why||[r.type,r.as_owner,r.country,r.registrar].filter(Boolean).join(' | '))],
  ['Link',r=>tiLink(r.link,'open'),'nw']],1500,
  vt.enabled?`<p class="note">${esc(vt.checked||0)} checked (${esc(vt.sent||0)} requests sent, ${esc(vt.from_cache||0)} answered from the local cache), `
   +`${esc(vt.not_checked||0)} not checked. Pace: ${esc(vt.rate_per_min)} per minute, at most ${esc(vt.max_lookups)} new lookups per run. `
   +'What was sent: threat_intelligence/vt_sent.txt. Raw answers: threat_intelligence/vt/.</p>'
   :'<p class="note">VirusTotal was off for this run (no API key given). Everything else on this page was checked locally.</p>');
 const DB=T.databases||[];
 h+=tiSec('Databases used and their age','tiDb',DB,[
  ['Database',r=>`<b>${esc(r.name)}</b><div class="dim">${esc(r.why)}</div>`],['Contains',r=>esc(r.what),'nw'],
  ['Copy',r=>r.present?esc(r.where):(r.needs_key?'needs an abuse.ch key':'not downloaded'),'nw'],
  ['Fetched',r=>esc(r.fetched),'nw'],['Age',r=>r.age_days==null?'':(r.stale?tiPill('stale')+' ':'')+esc(r.age_days+' days'),'nw'],
  ['Entries',r=>esc(r.entries==null?'':r.entries),'nw'],['Licence',r=>esc(r.licence)]],100,
  '<p class="note">All of these are read on this PC. Bundled copies ship with RAMBreaker; the others are fetched only when you choose '
  +'<b>Update</b> in the settings, because their terms do not allow redistribution.</p>');
 const QO={complete:0,partial:1,rebuilt:2,region:3,empty:9},qo=r=>r.quality in QO?QO[r.quality]:5;  /* objects with content first: a Linux page cache lists 25,000+ files with no cached page */
 const INV=(T.inventory||[]).map((r,i)=>[r,i]).sort((a,b)=>(qo(a[0])-qo(b[0]))||(a[1]-b[1])).map(x=>x[0]);
 const nEmpty=INV.filter(r=>r.quality==='empty').length;
 h+=tiSec('Everything that was dumped','tiInv',INV,[
  ['Kind',r=>esc(r.kind),'nw'],['Name',r=>esc(r.name)],['Path',r=>esc(r.path)],
  ['Process',r=>r.pid?esc((r.process||'')+' ('+r.pid+')'):'','nw'],['Size',r=>esc(r.size),'nw'],['Type',r=>esc(r.type),'nw'],
  ['Hash quality',r=>tiPill(r.quality),'nw'],['Location',r=>r.location&&r.location!=='other'?tiPill(r.location):'','nw'],
  ['VirusTotal',r=>esc(r.vt||''),'nw'],['SHA-256',r=>esc(r.sha256),'nw'],['Dumped file',r=>esc(r.file),'nw']].filter(noVT),2000,
  '<p class="note">One row per dumped object, objects with content first'+(nEmpty?` (${esc(nEmpty)} with nothing recoverable are listed last)`:'')+'. Files are under threat_intelligence/dumps/ next to this report.</p>');
 const dm=T.dumps||{},tm=T.timings||{};
 h+='<div class="card"><h2>Dump statistics</h2><div class="grid">'
  +['files','processes','regions'].map(k=>`<div class="stat"><div class="n">${esc((dm[k]||{}).ok||0)}</div><div class="l">${k}: ok `
   +`(${esc((dm[k]||{}).empty||0)} empty, ${esc((dm[k]||{}).failed||0)} failed)</div></div>`).join('')+'</div>'
  +'<p class="note">Step times (s): '+Object.entries(tm).map(([k,v])=>esc(k+' '+v)).join(', ')+'</p></div>';
 el.innerHTML=h;
}
"""
