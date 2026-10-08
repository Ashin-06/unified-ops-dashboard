'use strict';
let socFilter='',socQuery='';
const socWrite=()=>['admin','analyst'].includes(state.identity?.role);
async function securityView(view){
 if(!state.token)return panel('Unlock the security workspace','Use your individual access key',`<div class="info-copy"><p>Security evidence requires authentication. Investigate signals collected by this dashboard.</p><button class="button primary" id="unlockButton">Unlock workspace</button></div>`);
 const generation=state.generation,who=await api('/api/soc/me');
 if(generation!==state.generation)return '';
 state.identity=who;
 if(['access','activity'].includes(view)&&who.role!=='admin')return empty('Administrator access required','Your current role is '+who.role);
 if(view==='detections'){
  const data=await api('/api/soc/detections');
  return panel('Detection findings',esc(data.coverage),`<div class="info-copy"><p>${data.records_checked} records checked · ${data.findings.length} matching patterns. ${data.capped?'Scan limit reached; results are incomplete.':''}</p><p>${data.records_checked?'A match is a reason to investigate, not proof of compromise.':'No recent traffic available. Configure traffic collection before expecting findings.'}</p><p>Checks run when this page is opened or refreshed. Saving findings creates deduplicated incidents; nothing is blocked automatically.</p></div>`+table(['Rule','Host / observed source','Observed / threshold','Evidence','Explanation'],data.findings.map(r=>[esc(r.title),esc(r.hostname)+'<br>'+esc(r.source_ip),`${r.count} / ${r.threshold} ${esc(r.unit)}`,esc(r.evidence_ids.join(', ')),esc(r.explanation)])),`<button class="button primary" data-sync="detection" ${socWrite()?'':'disabled'}>Save findings to inbox</button>`)+panel('Detection rules','Tune thresholds or disable expected patterns. Only administrators can change rules.',data.rules.map(r=>`<form class="form-body detectionRule" data-rule="${esc(r.id)}"><h3>${esc(r.name)}</h3><p>${esc(r.description)}</p><label><input type="checkbox" name="enabled" ${r.enabled?'checked':''} ${who.role==='admin'?'':'disabled'}> Enabled</label> <label>Threshold <input type="number" name="threshold" min="2" max="10000" required value="${r.threshold}" ${who.role==='admin'?'':'disabled'}></label> <button class="button" ${who.role==='admin'?'':'disabled'}>Save rule</button></form>`).join(''));
 }
 if(view==='brief'){
  const data=await api('/api/soc/brief');
  return `<div class="metric-grid">${[['Open investigations',data.open_count],['Unassigned',data.unassigned_count],['Affected assets',data.affected_assets],['Resolved',data.resolved_count]].map(([label,value])=>`<article class="metric-card"><div class="metric-label">${esc(label)}</div><div class="metric-value">${value}</div></article>`).join('')}</div>`+panel('Your investigation priorities',esc(data.method),`<div class="info-copy"><p>${esc(data.scope)}${data.capped?' · Result limit reached; older incidents are omitted.':''}</p><p>Collect local alerts in the Incident inbox and anomaly findings in Anomaly insights to include them here.</p></div>`+table(['Priority','Investigation','Asset / owner','Why this comes first','Suggested next steps'],data.queue.map(r=>[badge(r.priority_score+'/100'),`<button class="text-button" data-incident="${r.id}">${esc(r.title)}</button>`,`${esc(r.asset)}<br>${esc(r.owner||'Unassigned')}`,r.reasons.map(esc).join('<br>'),r.next_steps.map(esc).join('<br>')])),`<button class="button" id="downloadBrief">Download handover</button>`);
 }
 if(view==='incidents'){
  const rows=await api('/api/soc/incidents?q='+encodeURIComponent(socQuery)+(socFilter?'&status='+socFilter:''));
  return panel('Incident inbox','Latest 200 incidents · grouped by matching asset and category within 24 hours. Grouping is a heuristic, not proof of a shared cause.',`<form id="socSearch" class="form-body"><label for="socQuery">Search title or asset</label> <input id="socQuery" name="q" maxlength="200" value="${esc(socQuery)}"><label for="socStatus">Status</label> <select id="socStatus" name="status">${['','new','investigating','resolved'].map(v=>`<option value="${v}" ${v===socFilter?'selected':''}>${v||'All statuses'}</option>`).join('')}</select> <button class="button">Search</button></form>`+table(['Incident','Asset','Severity','Status','Owner','Sources','Evidence'],rows.map(r=>[`<button class="text-button" data-incident="${r.id}">${esc(r.title)}</button>`,esc(r.asset),badge(r.severity),badge(r.status),esc(r.owner||'Unassigned'),esc(r.sources),r.event_count])),`<button class="button" data-sync="local" ${socWrite()?'':'disabled'}>Collect local alerts</button>`);
 }
 if(view==='insights'){
  const data=await api('/api/soc/insights');
  return panel('Explainable anomaly signals',esc(data.method),`<div class="info-copy"><p>${data.hosts_checked} hosts checked. ${data.warming_up.length} still collecting a baseline. Spikes are investigation signals, not malware verdicts.</p></div>`+table(['Host','Metric','Current','Baseline','Explanation'],data.findings.map(r=>[esc(r.hostname),esc(r.metric),percent(r.current),percent(r.baseline),esc(r.explanation)])),`<button class="button" data-sync="anomaly" ${socWrite()?'':'disabled'}>Import findings into inbox</button>`);
 }
 if(view==='access'){
  const rows=await api('/api/soc/users');
  return panel('Individual access keys','Viewer: read. Analyst: read, import and investigate. Administrator: all operations.',`<form id="socUser" class="form-body"><label for="socName">User name</label> <input id="socName" name="name" required minlength="3" maxlength="80" pattern="[a-zA-Z0-9_.@-]+" autocomplete="off"><label for="socRole">Role</label> <select id="socRole" name="role"><option>viewer</option><option>analyst</option><option>admin</option></select> <button class="button primary">Create key</button></form>`+table(['Name','Role','Status','Created','Action'],rows.map(r=>[esc(r.name),esc(r.role),r.enabled?'Active':'Revoked',esc(timestamp(r.created_at)),r.enabled?`<button class="text-button" data-revoke="${r.id}">Revoke</button>`:'—'])));
 }
 const rows=await api('/api/soc/audit');
 return panel('Activity audit','Latest 500 mutation attempts. Request bodies and access keys are excluded. This local record is not a tamper-proof compliance archive.',table(['Time','Actor','Role','Action','Target','HTTP result'],rows.map(r=>[esc(timestamp(r.timestamp)),esc(r.actor),esc(r.role),esc(r.action),esc(r.target),r.outcome])));
}
const socDialog=document.createElement('dialog');socDialog.id='socDialog';socDialog.setAttribute('aria-labelledby','socTitle');document.body.append(socDialog);
socDialog.addEventListener('close',()=>{socDialog.innerHTML='';});
function socModal(title,body){socDialog.innerHTML=`<div class="dialog-heading"><h2 id="socTitle">${esc(title)}</h2><button class="icon-button" id="socClose" aria-label="Close">×</button></div>${body}`;socDialog.showModal();}
async function showIncident(id){
 const generation=state.generation,token=state.token;
 const data=await api('/api/soc/incidents/'+id),r=data.incident;
 if(generation!==state.generation||token!==state.token)return;
 socModal('Incident #'+id,`<h3>${esc(r.title)}</h3><p>${esc(r.asset)} · ${esc(r.severity)} · ${esc(r.status)}</p>${socWrite()?`<form id="socEdit" data-id="${id}"><div class="field"><label for="incidentStatus">Status</label><select id="incidentStatus" name="status">${['new','investigating','resolved'].map(v=>`<option ${r.status===v?'selected':''}>${v}</option>`).join('')}</select></div><div class="field"><label for="incidentOwner">Owner</label><input id="incidentOwner" name="owner" maxlength="100" value="${esc(r.owner)}"></div><div class="field"><label for="incidentNote">Investigation note</label><textarea id="incidentNote" name="note" maxlength="4000" rows="3"></textarea></div><button class="button primary">Save investigation</button></form>`:''}<h3>Evidence · latest 500</h3>${data.events.map(e=>`<details><summary>${esc(e.source)} · ${esc(e.title)}</summary><p>${esc(timestamp(e.occurred_at))} · Signal status: ${esc(e.vendor_status)}</p><p style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(e.description)}</p></details>`).join('')}<h3>Timeline · latest 500</h3>${data.timeline.map(t=>`<p><strong>${esc(t.actor)}</strong> · ${esc(timestamp(t.timestamp))}<br>${esc(t.message)}</p>`).join('')}`);
}
document.addEventListener('click',async e=>{
 try{
  if(e.target.closest('#downloadBrief')){
   const data=await api('/api/soc/brief');
   const lines=['OPERATIONS HANDOVER', 'Generated: '+data.generated_at,data.scope,data.method,
    'Open: '+data.open_count+' | Unassigned: '+data.unassigned_count+' | Affected assets: '+data.affected_assets,
    data.capped?'Result limit reached; older incidents omitted.':'',
    ...data.queue.flatMap(r=>['','Incident #'+r.id+': '+r.title,'Priority: '+r.priority_score+'/100','Asset: '+r.asset+' | Owner: '+(r.owner||'Unassigned'),'Status: '+r.status,'Reasons: '+r.reasons.join('; '),...r.next_steps.map(t=>'[ ] '+t)])];
   const url=URL.createObjectURL(new Blob([lines.join('\n')],{type:'text/plain;charset=utf-8'}));
   const a=document.createElement('a');a.href=url;a.download='operations-handover.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  if(e.target.closest('#socClose'))socDialog.close();
  const incident=e.target.closest('[data-incident]');if(incident)await showIncident(Number(incident.dataset.incident));
  const sync=e.target.closest('[data-sync]');if(sync){sync.disabled=true;try{const data=await api('/api/soc/sync/'+sync.dataset.sync,{method:'POST',timeout:40000});toast(`${data.inserted} new signals; ${data.updated} existing signals updated. ${data.truncated?'Snapshot cap reached.':''}`);await refresh();}finally{if(sync.isConnected)sync.disabled=false;}}
  const revoke=e.target.closest('[data-revoke]');if(revoke&&await promptAction('Revoke this key?','The user will lose authenticated access immediately.','','Revoke')){await api('/api/soc/users/'+revoke.dataset.revoke,{method:'DELETE'});toast('Access key revoked');await refresh();}
 }catch(error){toast(error.message);}
});
document.addEventListener('submit',async e=>{
 if(!['socSearch','socUser','socEdit'].includes(e.target.id))return;
 e.preventDefault();const form=e.target,values=Object.fromEntries(new FormData(form)),button=form.querySelector('button');button.disabled=true;
 try{
  if(form.id==='socSearch'){socQuery=values.q;socFilter=values.status;await refresh();}
  if(form.id==='socEdit'){await api('/api/soc/incidents/'+form.dataset.id,{method:'PATCH',body:JSON.stringify(values)});socDialog.close();toast('Investigation saved');await refresh();}
  if(form.id==='socUser'){const result=await api('/api/soc/users',{method:'POST',body:JSON.stringify(values)});socModal('Save this key now',`<p>Access key for ${esc(result.name)} (${esc(result.role)}). It is shown once. Store it securely before closing.</p><label for="newAccessKey">One-time access key</label><input id="newAccessKey" readonly autocomplete="off" value="${esc(result.api_key)}"><p>Closing clears the key from this page. If it is lost, revoke it and create a new user key.</p>`);await refresh();}
 }catch(error){toast(error.message);}finally{if(button.isConnected)button.disabled=false;}
});

document.addEventListener('submit',async e=>{
 if(!e.target.matches('.detectionRule'))return;
 e.preventDefault();const form=e.target,button=form.querySelector('button'),data=new FormData(form);button.disabled=true;
 try{await api('/api/soc/detections/rules/'+form.dataset.rule,{method:'PATCH',body:JSON.stringify({enabled:data.has('enabled'),threshold:Number(data.get('threshold'))})});toast('Detection rule updated');await refresh();}catch(error){toast(error.message);}finally{if(button.isConnected)button.disabled=false;}
});
