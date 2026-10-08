'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const icons = {
 overview:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
 servers:'M4 3h16v7H4z M4 14h16v7H4z M7 6h1 M7 17h1 M12 6h5 M12 17h5',
 processes:'M8 3v3 M16 3v3 M8 18v3 M16 18v3 M3 8h3 M3 16h3 M18 8h3 M18 16h3 M6 6h12v12H6z M9 9h6v6H9z',
 connections:'M3 6h6v6H3z M15 12h6v6h-6z M9 9h9v3 M6 12v6h9',
 requests:'M3 12h4l3-8 4 16 3-8h4',
 alerts:'M12 3l10 18H2z M12 9v5 M12 17h.01',
 logs:'M5 3h10l4 4v14H5z M14 3v5h5 M8 12h8 M8 16h6',
 integrations:'M8 3v5 M16 3v5 M6 8h12v4a6 6 0 0 1-12 0z M12 18v3',
 settings:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M19 5l-2 2 M7 17l-2 2',
 memory:'M3 6h18v12H3z M6 9v5 M10 9v5 M14 9v5 M18 9v5 M6 18v3 M12 18v3 M18 18v3',
 disk:'M5 3h14l3 16H2z M3 14h18 M15 17h.01 M18 17h.01',
 security:'M12 2l9 4v6c0 5-9 10-9 10S3 17 3 12V6z M8 12l3 3 5-6'
};
const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${icons[name] || icons.overview}"/></svg>`;
const views = {
 overview:['Overview','A live pulse on your systems. Everything you need, in one place.'],
 servers:['Servers','Keep every host in view, and spot stale or disconnected systems.'],
 processes:['Processes','Understand resource usage and manage running processes.'],
 services:['Services','Check the status of configured operating system services.'],
 connections:['Connections','Inspect active network connections on the selected server.'],
 requests:['Traffic','Explore observed traffic when packet capture is enabled.'],
 alerts:['Alerts','The signals that need your attention, with context to act.'],
 logs:['Logs','Search and filter the latest log entries from your systems.'],
 detections:['Detections','Find suspicious traffic patterns with explainable local rules.'],
 brief:['Operations brief','Know what needs attention, why it matters, and what to do next.'],
 incidents:['Incident inbox','Investigate grouped alerts and anomalies from your systems.'],
 insights:['Anomaly insights','Explainable resource spikes from your own collected history.'],
 access:['Team access','Issue and revoke individual viewer, analyst and administrator keys.'],
 activity:['Activity audit','Review authenticated changes and denied operations.'],
 integrations:['Integrations','Bring your security and infrastructure tools into one workspace.'],
 security:['Port scanner','Check open ports on systems you manage.'],
 help:['Help & about','A practical guide to your operations workspace.'],
 privacy:['Privacy','Understand what this workspace stores and shares.'],
 settings:['Settings','Tune your alerts and manage operator access.']
};
const state = {view:'overview',page:1,pageSize:50,host:'',local:'',servers:[],dataHost:'',paused:false,busy:false,token:'',generation:0,rows:[],sort:'cpu',query:'',level:'',logFile:'',history:[],stats:null,interval:Math.max(5000,Number(document.body.dataset.pollInterval)||15000),timer:null,abort:null};
try { document.documentElement.dataset.theme = localStorage.getItem('ops-theme') || 'light'; } catch {}
$('navigation').innerHTML = Object.entries(views).filter(([key])=>key!=='privacy').map(([key,[label]],i) => `${key==='integrations'?'<p class="nav-label nav-separator">MANAGE</p>':''}<button class="nav-link" data-view="${key}">${icon(key)}<span>${label}</span>${key==='alerts'?'<span class="count" id="alertCount">0</span>':''}</button>`).join('');
const num = (n,d=1) => Number.isFinite(Number(n)) ? Number(n).toLocaleString(undefined,{maximumFractionDigits:d,minimumFractionDigits:d}) : '—';
const percent = n => `${num(n)}%`;
const timestamp = t => { if (!t) return '—'; const d=new Date(t); return Number.isNaN(d.getTime()) ? String(t) : d.toLocaleString(); };
const relative = t => {const secs=(Date.now()-new Date(t).getTime())/1000; if(!Number.isFinite(secs))return t||'Never'; if(secs<60)return 'Just now'; if(secs<3600)return `${Math.floor(secs/60)}m ago`; if(secs<86400)return `${Math.floor(secs/3600)}h ago`;return `${Math.floor(secs/86400)}d ago`;};
const uptime = n => `${Math.floor(n/86400)}d ${Math.floor(n%86400/3600)}h ${Math.floor(n%3600/60)}m`;
const rate = n => n>=1024 ? `${num(n/1024)} MB/s` : `${num(n)} KB/s`;
const badge = (label,type='') => `<span class="badge ${type}">${esc(label)}</span>`;
const empty = (title,description='',symbol='✓') => `<div class="empty-state"><div class="empty-symbol">${symbol}</div><strong>${esc(title)}</strong><p>${esc(description)}</p></div>`;
const hostParam = () => `hostname=${encodeURIComponent(state.host)}`;
const panel = (title,description,body,actions='') => `<article class="panel"><div class="panel-heading"><div><h2>${title}</h2>${description?`<p>${description}</p>`:''}</div><div class="panel-actions">${actions}</div></div>${body}</article>`;
let toastTimer;
function toast(message){$('toast').textContent=message;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,4500);}
async function api(path,options={}) {
 const controller=new AbortController(); const parent=options.signal;
 const cancel=()=>controller.abort(); parent?.addEventListener('abort',cancel,{once:true});
 if(parent?.aborted)controller.abort(); const timeout=setTimeout(cancel,options.timeout||20000);
 try{
  const headers={'Accept':'application/json',...options.headers};
  if(state.token)headers.Authorization=`Bearer ${state.token}`;
  if(options.body)headers['Content-Type']='application/json';
  const response=await fetch(path,{...options,headers,signal:controller.signal});
  let data;try{data=await response.json();}catch{throw new Error('The server returned an unreadable response.');}
  if(!response.ok){const detail=Array.isArray(data.detail)?data.detail.map(x=>x.msg).join('; '):data.detail;const err=new Error(response.status===401?'Operator access is required. Unlock this session in Settings.':detail||`Request failed (${response.status})`);err.status=response.status;throw err;}
  if(data?.error || data?.status==='error')throw new Error(data.message || data.error || 'The operation failed.');
  if(response.headers.get('X-Audit-Status')==='failed'){ $('errorBanner').textContent='The action completed, but its audit entry could not be saved. Check server storage before further changes.';$('errorBanner').hidden=false;toast('Action completed; audit entry not saved. Check server storage.'); }
  return data;
 }finally{clearTimeout(timeout);parent?.removeEventListener('abort',cancel);}
}
function table(headers,rows,id='dataTable'){
 return `<div class="table-wrap"><table id="${id}"><thead><tr>${headers.map(x=>`<th scope="col">${x}</th>`).join('')}</tr></thead><tbody>${rows.length?rows.map(c=>`<tr>${c.map(x=>`<td>${x}</td>`).join('')}</tr>`).join(''):`<tr><td colspan="${headers.length}" class="no-results">No matching records.</td></tr>`}</tbody></table></div>`;
}
function spark(values,color='var(--accent)'){
 if(values.length<2)return `<span class="muted">Collecting</span>`;
 const vals=values.slice(-24),max=Math.max(...vals,1),min=Math.min(...vals,0);
 return `<svg class="sparkline" viewBox="0 0 80 25" aria-hidden="true"><polyline points="${vals.map((v,i)=>`${i*80/(vals.length-1)},${23-(v-min)/(max-min||1)*20}`).join(' ')}" fill="none" stroke="${color}" stroke-width="1.5"/></svg>`;
}
function chart(rows,keys,unit='%',id='chart'){
 if(!rows.length)return `<div class="chart-container">${empty('Waiting for samples','History will appear as the collector gathers data.','∿')}</div>`;
 const step=Math.max(1,Math.ceil(rows.length/180));const points=[];
 for(let i=0;i<rows.length;i+=step){const chunk=rows.slice(i,i+step),p={timestamp:chunk[0].timestamp};keys.forEach(k=>p[k]=Math.max(...chunk.map(r=>Number(r[k])||0)));points.push(p);}
 const w=640,h=205,left=42,right=10,top=10,bottom=28,pw=w-left-right,ph=h-top-bottom;
 const max=unit==='%'?100:Math.max(1,...points.flatMap(p=>keys.map(k=>Number(p[k])||0)))*1.15;
 const colors=['var(--accent)','var(--purple)'];
 let svg=`<svg class="chart" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="${esc(keys.join(' and '))} over time in ${unit}"><defs><linearGradient id="${id}Fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#42aa8b" stop-opacity=".14"/><stop offset="100%" stop-color="#42aa8b" stop-opacity=".01"/></linearGradient></defs>`;
 for(let i=0;i<5;i++){const y=top+i*ph/4;svg+=`<line x1="${left}" x2="${w-right}" y1="${y}" y2="${y}"/><text x="${left-10}" y="${y+3}" text-anchor="end">${num(max*(1-i/4),0)}${unit==='%'?'%':''}</text>`;}
 keys.forEach((k,j)=>{const coords=points.map((p,i)=>[left+(points.length===1?.5:i/(points.length-1))*pw,top+(1-(Number(p[k])||0)/max)*ph]);if(j===0 && coords.length>1)svg+=`<polygon points="${coords[0][0]},${top+ph} ${coords.map(c=>c.join(',')).join(' ')} ${coords.at(-1)[0]},${top+ph}" fill="url(#${id}Fill)"/>`;svg+=`<polyline points="${coords.map(c=>c.join(',')).join(' ')}" fill="none" stroke="${colors[j]}" stroke-width="2" vector-effect="non-scaling-stroke"/>`;if(coords.length===1)svg+=`<circle cx="${coords[0][0]}" cy="${coords[0][1]}" r="3" fill="${colors[j]}"/>`;});
 [...new Set([0,Math.floor((points.length-1)/2),points.length-1])].forEach(i=>{const x=left+(points.length===1?.5:i/(points.length-1))*pw;svg+=`<text x="${x}" y="${h-5}" text-anchor="${i===0&&points.length>1?'start':i===points.length-1&&points.length>1?'end':'middle'}">${esc(new Date(points[i].timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}))}</text>`;});
 return `<div class="chart-container">${svg}</svg></div>`;
}
function serverRows(servers){return servers.map(s=>[`<div class="hostname"><span class="host-icon">▤</span><div>${esc(s.hostname)}<small>${s.hostname===state.local?'Local collector':'Remote agent'}</small></div></div>`,badge(s.status,s.status==='Online'?'':s.status==='Warning'?'warning':'error'),esc(relative(s.last_seen)),`<button class="text-button" data-host="${esc(s.hostname)}">Inspect ↗</button>`]);}
function alertList(alerts){return alerts.length?alerts.map(a=>`<div class="alert-item"><span class="alert-icon">${a.level==='error'?'!':'↗'}</span><div><p>${esc(a.message)}</p><small>${esc(a.hostname)} · ${esc(a.category||'system')}</small></div><time title="${esc(timestamp(a.timestamp))}">${esc(relative(a.timestamp))}</time></div>`).join(''):empty('All quiet here','No alerts for this server. New signals will appear here.');}
async function overview(){
 const generation=state.generation;
 const [stats,history,servers,alerts,integrations,thresholds]=await Promise.all([api(`/api/stats?${hostParam()}`),api(`/api/metrics?range=${$('rangeSelect').value}&${hostParam()}`),api('/api/server-status'),api(`/api/alerts?${hostParam()}`),api('/api/integrations/status'),api('/api/config/alerts')]);
 if(generation!==state.generation)throw new Error('View changed');
 state.stats=stats;state.history=history;state.rows=history;
 const current=servers.find(s=>s.hostname===state.host),fresh=current?.status==='Online' && stats.source!=='stored';
 const metric=(label,value,key,glyph,threshold)=>`<article class="metric-card"><div class="metric-label">${label}${icon(glyph)}</div><div class="metric-value">${num(value)}<small>%</small></div><div class="metric-footer"><span class="metric-note ${value>=threshold?'warning':''}">${value>=threshold?'↑ Above threshold':'↗ Within threshold'}</span>${spark(history.map(r=>r[key]),key==='memory'?'var(--purple)':'var(--accent)')}</div></article>`;
 const last=history.at(-1)||{};
 return `<div class="summary-strip"><span class="summary-status"><span class="status-dot ${fresh?'':'warning'}"></span><strong>${stats.source==='stored'?'Agent unavailable · showing saved metrics':fresh?'Receiving system metrics':'Waiting for fresh metrics'}</strong></span><span>${esc(state.host)} · Uptime ${uptime(stats.uptime||0)}</span></div>
 <div class="metric-grid">${metric('CPU utilization',stats.cpu,'cpu','processes',thresholds.cpu_threshold??80)}${metric('Memory usage',stats.memory,'memory','memory',thresholds.memory_threshold??80)}<article class="metric-card"><div class="metric-label">Disk usage${icon('disk')}</div><div class="metric-value">${num(stats.disk)}<small>%</small></div><div class="metric-footer"><span class="metric-note ${stats.disk>=(thresholds.disk_threshold??90)?'warning':''}">${stats.disk>=(thresholds.disk_threshold??90)?'↑ Above threshold':'↗ Within threshold'}</span><span>${num(100-(stats.disk||0),0)}% available</span></div></article><article class="metric-card"><div class="metric-label">Network connections${icon('connections')}</div><div class="metric-value">${num(stats.total_connections,0)}</div><div class="metric-footer"><span class="metric-note">Current connections</span><span>All protocols</span></div></article></div>
 <div class="chart-grid">${panel('Resource activity','CPU and memory utilization over time',chart(history,['cpu','memory'],'%','resource')+`<div class="panel-foot"><span>${history.length} collected samples</span><span>CPU <strong>${percent(stats.cpu)}</strong> &nbsp; Memory <strong>${percent(stats.memory)}</strong></span></div>`,'<span class="legend"><span class="legend-dot"></span> CPU</span><span class="legend"><span class="legend-dot purple"></span> Memory</span>')}${panel('Network throughput','Traffic across network interfaces · KB/s',chart(history,['net_recv_rate','net_sent_rate'],'KB/s','network')+`<div class="panel-foot"><span>↓ In <strong>${rate(last.net_recv_rate||0)}</strong></span><span>↑ Out <strong>${rate(last.net_sent_rate||0)}</strong></span></div>`,'<span class="legend"><span class="legend-dot"></span> In</span><span class="legend"><span class="legend-dot purple"></span> Out</span>')}</div>
 <div class="bottom-grid">${panel('Server fleet',`${servers.length} monitored ${servers.length===1?'server':'servers'}`,table(['Server','Status','Last seen',''],serverRows(servers.slice(0,4)))+`<div class="panel-foot"><span>${servers.filter(s=>s.status==='Online').length} online</span><span>Last seen reflects collector samples</span></div>`,'<button class="text-button" data-view="servers">View all servers →</button>')}${panel('Recent alerts','The latest signals from this server',alertList(alerts.slice(0,3)),'<button class="text-button" data-view="alerts">View all →</button>')}</div>
 <div class="integrations-strip"><span>CONNECTED TOOLS</span>${Object.entries(integrations).map(([k,v])=>`<span class="integration-chip"><span class="status-dot ${v.enabled?'on':''}"></span>${esc(k[0].toUpperCase()+k.slice(1))}<span class="muted">${v.enabled?'Configured':'Not configured'}</span></span>`).join('')}<button class="text-button" data-view="integrations">Manage integrations →</button></div>`;
}
function searchRow(placeholder,extra=''){return `<div class="search-row"><div><input class="search-input" id="tableSearch" type="search" aria-label="${esc(placeholder)}" placeholder="${esc(placeholder)}" value="${esc(state.query)}">${extra}</div><span class="muted" id="rowCount">${state.rows.length} records</span></div>`;}
function filterRows(){const q=state.query.toLowerCase();return state.rows.filter(r=>Object.values(r).some(v=>String(v??'').toLowerCase().includes(q)));}
function renderRows(){
 const allRows=filterRows();
 const pages=Math.max(1,Math.ceil(allRows.length/state.pageSize));state.page=Math.min(state.page,pages);
 const rows=allRows.slice((state.page-1)*state.pageSize,state.page*state.pageSize);let html;
 if(state.view==='processes')html=table(['Process','PID','CPU','Memory','User',''],rows.map(p=>[esc(p.name),num(p.pid,0),percent(p.cpu),percent(p.memory),esc(p.user||'—'),`<button class="button small danger" data-kill="${Number(p.pid)}" data-process-host="${esc(state.dataHost)}" data-name="${esc(p.name)}">End process</button>`]));
 if(state.view==='services')html=table(['Service','Status'],rows.map(r=>[esc(r.name),badge(r.status,r.status==='active'?'':'warning')]));
 if(state.view==='connections')html=table(['Local address','Remote address','Status','PID'],rows.map(c=>[esc(c.local),esc(c.remote),badge(c.status,c.status==='ESTABLISHED'?'':'neutral'),esc(c.pid??'—')]));
 if(state.view==='requests')html=table(['Time','Protocol','Method','Path','Port','Status','Source IP'],rows.map(r=>[esc(timestamp(r.timestamp)),esc(r.protocol),esc(r.method),esc(r.path),esc(r.dst_port),esc(r.status_code),esc(r.src_ip)]));
 if(state.view==='servers')html=table(['Server','Status','Last seen',''],serverRows(rows));
 if(state.view==='alerts')html=alertList(rows);
 if(state.view==='logs')html=`<div class="log-view">${rows.length?rows.slice().reverse().map(l=>`<div class="log-line ${['error','warning'].includes(l.level)?l.level:''}">${esc(l.line)}</div>`).join(''):empty('No matching log entries','Try another level or search term.','≡')}</div>`;
 html+=`<div class="pagination"><span>${allRows.length?`${(state.page-1)*state.pageSize+1}–${Math.min(state.page*state.pageSize,allRows.length)} of ${allRows.length}`:'0 records'}</span><div><button class="button small" data-page="${state.page-1}" ${state.page===1?'disabled':''} aria-label="Previous page">← Previous</button><span>Page ${state.page} of ${pages}</span><button class="button small" data-page="${state.page+1}" ${state.page===pages?'disabled':''} aria-label="Next page">Next →</button></div></div>`;
 if($('rows'))$('rows').innerHTML=html;
 if($('rowCount'))$('rowCount').textContent=`${allRows.length} records`;
 return html;
}
async function listView(){
 const view=state.view,generation=state.generation,host=state.host,params=hostParam(),logFile=state.logFile,level=state.level;
 let rows=[];
 let extra='',description='';
 if(view==='processes'){rows=await api(`/api/processes?${params}&sort_by=${state.sort}&limit=250`);extra=`<label class="sr-only" for="sortSelect">Sort processes</label><select id="sortSelect"><option value="cpu" ${state.sort==='cpu'?'selected':''}>Highest CPU</option><option value="memory" ${state.sort==='memory'?'selected':''}>Highest memory</option></select>`;description='Up to 250 processes · CPU may exceed 100% on multicore systems';}
 if(view==='services'){rows=await api(`/api/services?${params}`);description='Configured services · Windows service status is supported';}
 if(view==='servers'){rows=await api('/api/server-status');extra='<button class="button small" id="compareServers">Compare resources</button>';description='Online: seen within 5 minutes · Warning: within 30 minutes';}
 if(view==='connections'){rows=await api(`/api/connections?${params}&limit=500`);description='Up to 500 current connections';}
 if(view==='requests'){rows=await api(`/api/requests?${params}&limit=250`);description='Up to 250 captured packets · Capture is opt-in; encrypted payloads are not decoded';}
 if(view==='alerts'){rows=await api(`/api/alerts?${params}`);extra='<button class="button small danger" id="clearAlerts">Clear server alerts</button>';description='Up to 200 recent alerts for the selected server';}
 if(view==='logs'){const files=await api(`/api/log-files?${params}`);const data=await api(`/api/logs?${params}&file=${encodeURIComponent(logFile)}${level?`&level=${level}`:''}`);rows=data.logs||[];extra=`<label class="sr-only" for="logFileSelect">Log file</label><select id="logFileSelect"><option value="">Default log</option>${(files.log_files||[]).map(f=>`<option value="${esc(f)}" ${state.logFile===f?'selected':''}>${esc(f)}</option>`).join('')}</select><button class="button small" id="analyzeLogs">Analyze log</button><label class="sr-only" for="levelSelect">Log level</label><select id="levelSelect">${[['','All levels'],['error','Errors'],['warning','Warnings'],['info','Info']].map(([v,l])=>`<option value="${v}" ${state.level===v?'selected':''}>${l}</option>`).join('')}</select>`;description='Latest entries from the default configured log';}
 if(generation!==state.generation)throw new Error('View changed');
 if(!Array.isArray(rows))throw new Error('The server returned an unexpected data format.');
 state.rows=rows;state.dataHost=host;
 return panel(views[state.view][0],description,searchRow(`Search ${views[state.view][0].toLowerCase()}…`,extra)+`<div id="rows">${renderRows()}</div><div id="extraResults"></div>`);
}
async function integrationView(){
 const generation=state.generation;
 const configs=await api('/api/integrations/status');
 const details={wazuh:['W','Security monitoring','Agent visibility and security events from your Wazuh manager.'],zabbix:['Z','Infrastructure monitoring','Host availability, triggers, and active infrastructure problems.'],grafana:['G','Dashboards & visualization','Open your Grafana dashboards for deeper analysis.']};
 const cards=await Promise.all(Object.entries(configs).map(async([name,cfg])=>{let status='Not configured',type='neutral',summary='Enable this integration in config.json to get started.';
 if(cfg.enabled && name!=='grafana'){try{const data=await api(`/api/${name}/stats`);status=data.status==='connected'?'Connected':data.status||'Unknown';type=status==='Connected'?'':'warning';summary=name==='wazuh'?`${data.agents?.active??0} active / ${data.agents?.total??0} total agents`:`${data.active_hosts??0} active / ${data.total_hosts??0} total hosts`;}catch(e){status='Unavailable';type='error';summary=e.message;}}
 if(cfg.enabled&&name==='grafana'){status='Configured';type='';summary='Open the configured dashboard to check availability.';}
 let url='';try{const u=new URL(cfg.dashboard_url||cfg.url);if(['http:','https:'].includes(u.protocol))url=u.href;}catch{}
 const [letter,title,desc]=details[name];return `<article class="panel integration-card"><div class="integration-logo">${letter}</div><h2>${name[0].toUpperCase()+name.slice(1)}</h2><p>${title}<br>${desc}</p>${badge(status,type)}<p>${esc(summary)}</p>${cfg.enabled&&url?`<a class="button" href="${esc(url)}" target="_blank" rel="noopener noreferrer">Open ${name} ↗</a>`:'<button class="text-button" data-view="settings">Setup information →</button>'}</article>`;}));
 if(generation!==state.generation)throw new Error('View changed');
 state.rows=Object.entries(configs).map(([name,cfg])=>({name,enabled:cfg.enabled}));
 return `<div class="integration-grid">${cards.join('')}</div>`;
}
async function settingsView(){
 const data=await api('/api/config/alerts');
 const fields=[['cpu_threshold','CPU threshold','%',100],['memory_threshold','Memory threshold','%',100],['disk_threshold','Disk threshold','%',100],['alert_cooldown_seconds','Alert cooldown','seconds',86400]];
 return `<div class="settings-grid">${panel('Alert thresholds','Choose when your systems should raise a signal',`<form id="settingsForm"><div class="form-body form-grid">${fields.map(([key,label,unit,max])=>`<div class="field"><label for="${key}">${label}</label><input id="${key}" name="${key}" type="number" required min="0" max="${max}" value="${Number(data[key]??0)}"><small>${unit==='%'?'Percent utilization (0–100)':'Seconds between repeat alerts'}</small></div>`).join('')}</div><div class="form-actions"><button class="button primary" type="submit">Save changes</button></div></form>`)}<div>${panel('Operator access','Administrative changes require your API key',`<div class="info-copy"><p>Your key is held in memory for this tab and cleared when you reload. Find <code>master_api_key</code> in your local <code>config.json</code>.</p><button class="button" id="unlockButton">${state.token?'Replace session key':'Unlock operator actions'}</button>${state.token?'<button class="text-button" id="lockButton">Lock session</button>':''}</div>`)}<br>${panel('Workspace configuration','',`<div class="info-copy"><p>Manage remote agents, log paths, and integration credentials in <code>config.json</code>, then restart the dashboard.</p><p>See Help for setup and troubleshooting. Packet capture is disabled by default.</p></div>`)}<br>${preferencesPanel()}</div></div>`;
}
function scanView(){return panel('Port scanner','Scan only systems you own or are authorized to test',`<form id="scanForm"><div class="form-body form-grid"><div class="field"><label for="scanTarget">Target hostname or IPv4 address</label><input id="scanTarget" required placeholder="127.0.0.1" maxlength="253"></div><div class="field"><label for="scanPorts">Ports to check</label><input id="scanPorts" required value="22,80,443,3389,8080"><small>Comma-separated ports, up to 128</small></div></div><div class="form-actions"><button class="button primary" type="submit">Run scan</button></div></form><div id="scanResults"></div>`);}
async function refresh(manual=false){
 if(state.busy)return;
 state.busy=true;const generation=state.generation;$('refreshButton').disabled=true;$('view').setAttribute('aria-busy','true');
 try{
  let html;
  if(state.view==='overview')html=await overview();
  else if(state.view==='integrations')html=await integrationView();
  else if(state.view==='settings')html=await settingsView();
  else if(state.view==='security')html=scanView();
  else if(state.view==='help')html=helpView();
  else if(state.view==='privacy')html=privacyView();
  else if(['detections','incidents','brief','insights','access','activity'].includes(state.view))html=await securityView(state.view);
  else html=await listView();
  if(generation!==state.generation)return;
  const active=document.activeElement,focusedId=active?.id,selection=active?.selectionStart;
  $('view').innerHTML=html;$('errorBanner').hidden=true;
  if(focusedId==='tableSearch'){$(focusedId)?.focus();if(selection!==null)$(focusedId)?.setSelectionRange(selection,selection);}
  $('lastUpdated').textContent=`Last updated ${new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})}`;
  if(manual)toast('Dashboard refreshed');
 }catch(e){if(generation===state.generation){ $('errorBanner').textContent=`${e.name==='AbortError'?'The server took too long to respond.':e.message} The last successful view is retained; it may be out of date.`;$('errorBanner').hidden=false;$('lastUpdated').textContent='Update failed · data may be stale';if(state.view==='settings')$('view').innerHTML=panel('Operator access','Unlock this session to load protected settings','<div class="info-copy"><button class="button" id="unlockButton">Unlock operator actions</button></div>');}}
 finally{$('view').setAttribute('aria-busy','false');state.busy=false;$('refreshButton').disabled=false;if(typeof updateSessionUi==='function')updateSessionUi();if(generation!==state.generation)void refresh();}
}
function navigate(view){
 if(!views[view]){toast('That page does not exist. Showing Overview.');view='overview';}
 state.generation++;state.view=view;state.query='';state.page=1;state.rows=[];state.history=[];state.stats=null;state.dataHost='';
 location.hash=view;document.title=`Unified Ops · ${views[view][0]}`;
 $('breadcrumb').textContent=views[view][0];$('pageTitle').textContent=views[view][0];$('pageDescription').textContent=views[view][1];
 document.querySelectorAll('.nav-link').forEach(el=>{const active=el.dataset.view===view;el.classList.toggle('active',active);if(active)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});
 $('rangeSelect').disabled=view!=='overview';$('exportButton').disabled=['settings','security','help','privacy','detections','incidents','brief','insights','access','activity'].includes(view);$('hostSelect').disabled=['settings','integrations','servers','help','privacy','detections','incidents','brief','insights','access','activity'].includes(view);
 $('sidebar').classList.remove('open');$('menuButton').setAttribute('aria-expanded','false');
 if(typeof syncMobileNavigation==='function')syncMobileNavigation();
 $('main').focus({preventScroll:true});
 $('view').innerHTML=empty('Loading workspace','Fetching the latest data…','∿');void refresh();
}
function promptAction(title,description,fields='',confirm='Continue'){
 if($('actionDialog').open)return Promise.resolve(null);
 $('dialogTitle').textContent=title;$('dialogDescription').textContent=description;$('dialogFields').innerHTML=fields;$('dialogConfirm').textContent=confirm;$('actionDialog').returnValue='';$('actionDialog').showModal();
 return new Promise(resolve=>$('actionDialog').addEventListener('close',()=>{const result=$('actionDialog').returnValue==='confirm'?{key:$('operatorKey')?.value,tree:$('killTree')?.checked}:null;$('dialogFields').replaceChildren();resolve(result);},{once:true}));
}
async function unlock(){const result=await promptAction('Operator access','Enter your individual access key or the bootstrap key from config.json. It stays in this tab until you reload.','<label class="sr-only" for="operatorKey">Master API key</label><input id="operatorKey" type="password" autocomplete="off" placeholder="Master API key" required>','Unlock');if(!result?.key)return false;state.token=result.key;try{state.identity=await api('/api/auth/check',{method:'POST'});toast('Operator session unlocked');if(typeof updateSessionUi==='function')updateSessionUi();return true;}catch(e){state.token='';throw e;}}
async function mutate(path,options){if(!state.token && !await unlock())return null;return api(path,options);}
function csvExport(){
 const rows=state.view==='overview'?state.history:filterRows();if(!rows.length){toast('No records to export yet');return;}
 const keys=[...new Set(rows.flatMap(Object.keys))];
 const cell=v=>{let s=String(v??'');if(/^[=+@\-\t\r]/.test(s))s="'"+s;return `"${s.replace(/"/g,'""')}"`;};
 const csv=[keys.map(cell).join(','),...rows.map(r=>keys.map(k=>cell(typeof r[k]==='object'?JSON.stringify(r[k]):r[k])).join(','))].join('\r\n');
 const url=URL.createObjectURL(new Blob(['\ufeff',csv],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=`unified-ops-${state.view}-${new Date().toISOString().slice(0,10)}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('Report exported');
}
async function health(){try{const [data,count]=await Promise.all([api('/api/health'),api('/api/alerts/count')]);$('collectorDot').className=`status-dot ${data.status==='healthy'?'':'warning'}`;$('collectorText').innerHTML=`${data.status==='healthy'?'Collector is running':'Collector or storage needs attention'}<small>${esc(data.hostname)}</small>`;$('alertCount').textContent=count.new_alerts;$('notificationDot').hidden=!count.new_alerts;}catch{$('collectorDot').className='status-dot error';$('collectorText').innerHTML='Collector unavailable<small>Check connection or operator access</small>';}}
async function discover(){const data=await api('/api/servers');state.servers=data.servers;state.local=data.local_hostname;state.host=state.host||state.local;$('hostSelect').innerHTML=state.servers.map(s=>`<option value="${esc(s)}">${esc(s)}${s===state.local?' (local)':''}</option>`).join('');$('hostSelect').value=state.host;}
document.addEventListener('click',async e=>{
 const nav=e.target.closest('[data-view]');if(nav){navigate(nav.dataset.view);return;}
 const host=e.target.closest('[data-host]');if(host){state.host=host.dataset.host;$('hostSelect').value=state.host;navigate('overview');return;}
 try{
  if(e.target.closest('#compareServers')){
   const hosts=state.servers.slice(0,20);const gen=state.generation;
   const rows=await Promise.all(hosts.map(async host=>{try{const d=await api(`/api/stats?hostname=${encodeURIComponent(host)}`);return [esc(host),percent(d.cpu),percent(d.memory),percent(d.disk),uptime(d.uptime||0)];}catch{return [esc(host),'Unavailable','—','—','—'];}}));
   if(gen===state.generation)$('extraResults').innerHTML='<div class="panel-heading"><h2>Resource comparison · up to 20 servers</h2></div>'+table(['Server','CPU','Memory','Disk','Uptime'],rows,'comparisonTable');
  }
  if(e.target.closest('#analyzeLogs')){const gen=state.generation;const d=await api(`/api/log-analysis?${hostParam()}&file=${encodeURIComponent(state.logFile)}`);if(gen===state.generation)$('extraResults').innerHTML=`<div class="info-copy"><h3>Log summary</h3><p>${num(d.errors,0)} errors · ${num(d.warnings,0)} warnings · ${num(d.info,0)} informational entries</p><p>Rule-based analysis of ${num(d.total_lines,0)} recent lines.</p>${(d.top_errors||[]).map(x=>`<div class="log-line">${esc(x)}</div>`).join('')}</div>`;}
  const kill=e.target.closest('[data-kill]');if(kill){const hostAtClick=kill.dataset.processHost;const result=await promptAction('End process?',`End ${kill.dataset.name} (PID ${kill.dataset.kill}) on ${hostAtClick}? Unsaved work in this process may be lost.`,'<label class="checkbox-field"><input id="killTree" type="checkbox"> Also end child processes</label>','End process');if(!result)return;const data=await mutate(`/api/processes/kill?hostname=${encodeURIComponent(hostAtClick)}`,{method:'POST',body:JSON.stringify({pid:Number(kill.dataset.kill),kill_tree:!!result.tree})});if(data){toast('Process ended');void refresh();}}
  if(e.target.closest('#unlockButton')){if(await unlock()){await discover();void refresh();void health();}}
  if(e.target.closest('#lockButton')){state.token='';toast('Operator session locked');void refresh();}
  if(e.target.closest('#clearAlerts')){const hostAtClick=state.host;const result=await promptAction('Clear server alerts?',`Delete all stored alerts for ${hostAtClick}? This cannot be undone.`,'','Clear alerts');if(result){const data=await mutate(`/api/alerts?hostname=${encodeURIComponent(hostAtClick)}`,{method:'DELETE'});if(data){toast('Alerts cleared');void refresh();void health();}}}
 }catch(err){toast(err.message);}
});
document.addEventListener('input',e=>{if(e.target.id==='tableSearch'){state.query=e.target.value;state.page=1;renderRows();}});
document.addEventListener('change',e=>{if(e.target.id==='sortSelect'){state.sort=e.target.value;state.generation++;void refresh();}if(e.target.id==='levelSelect'){state.level=e.target.value;state.generation++;void refresh();}if(e.target.id==='logFileSelect'){state.logFile=e.target.value;state.generation++;void refresh();}});
document.addEventListener('submit',async e=>{
 if(!['settingsForm','scanForm'].includes(e.target.id))return;e.preventDefault();const button=e.target.querySelector('[type=submit]');button.disabled=true;
 try{
  if(e.target.id==='settingsForm'){const data=Object.fromEntries([...new FormData(e.target)].map(([k,v])=>[k,Number(v)]));if(await mutate('/api/config/alerts',{method:'POST',body:JSON.stringify(data)}))toast('Alert thresholds saved');}
  else{const resultsEl=$('scanResults');const target=$('scanTarget').value.trim(),ports=$('scanPorts').value.trim();$('scanResults').innerHTML=empty('Checking ports','This may take a few seconds.','∿');const data=await mutate(`/api/security/port-scan?${hostParam()}`,{method:'POST',body:JSON.stringify({target,ports})});if(data)resultsEl.innerHTML=table(['Port','Service','Status'],data.results.map(r=>[esc(r.port),esc(r.service),badge(r.status,r.status==='open'?'':'neutral')]));else resultsEl.innerHTML='';}
 }catch(err){toast(err.message);if($('scanResults'))$('scanResults').innerHTML=empty('Scan could not complete',err.message,'!');}finally{button.disabled=false;}
});
$('refreshButton').addEventListener('click',async()=>{if(!state.host){try{await discover();}catch(e){toast(e.message);}}void refresh(true);void health();});
$('hostSelect').addEventListener('change',()=>{state.host=$('hostSelect').value;state.logFile='';navigate(state.view);});
$('rangeSelect').addEventListener('change',()=>{navigate(state.view);});
$('exportButton').addEventListener('click',csvExport);
$('pauseButton').addEventListener('click',()=>{state.paused=!state.paused;$('pauseButton').setAttribute('aria-pressed',state.paused);$('liveLabel').textContent=state.paused?'Paused':'Live';$('pauseButton').querySelector('.status-dot').classList.toggle('warning',state.paused);if(!state.paused)void refresh();});
$('themeButton').addEventListener('click',()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;try{localStorage.setItem('ops-theme',theme);}catch{}});
$('menuButton').addEventListener('click',()=>{const open=$('sidebar').classList.toggle('open');$('menuButton').setAttribute('aria-expanded',open);});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){$('sidebar').classList.remove('open');$('menuButton').setAttribute('aria-expanded','false');}});
window.addEventListener('hashchange',()=>{const view=location.hash.slice(1);if(view!==state.view)navigate(view);});
$('pollLabel').textContent=`${state.interval/1000}s`;
async function init(){try{await discover();}catch(e){$('errorBanner').textContent=e.message;$('errorBanner').hidden=false;}navigate(location.hash.slice(1)||'overview');void health();schedulePolling();}
window.addEventListener('DOMContentLoaded',()=>void init(),{once:true});
