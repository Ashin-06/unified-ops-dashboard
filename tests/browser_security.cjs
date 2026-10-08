const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{const browser=await chromium.launch({channel:'msedge',headless:true,args:['--disable-gpu']});try{
const page=await browser.newPage({viewport:{width:1360,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
const incident={id:1,title:'<img src=x onerror=alert(1)> evidence',asset:'host-a',severity:'high',status:'new',owner:'',sources:'local,anomaly',event_count:2};
await page.route('**/api/auth/check',r=>r.fulfill({json:{status:'success',name:'test-admin',role:'admin'}}));
await page.route('**/api/soc/**',r=>{const path=new URL(r.request().url()).pathname;let data=[];
if(path.endsWith('/me'))data={name:'test-admin',role:'admin'};
else if(path.endsWith('/incidents/1'))data=r.request().method()==='PATCH'?{status:'success'}:{incident,events:[{source:'local',title:incident.title,description:'<script>bad()</script>',vendor_status:'new'}],timeline:[{actor:'test-admin',message:'Observed'}]};
else if(path.endsWith('/incidents'))data=[incident];
else if(path.includes('/sync/'))data={inserted:1,updated:0};
else if(path.includes('/detections/rules/'))data={status:'success'};
else if(path.endsWith('/detections'))data={coverage:'Local traffic only',records_checked:10,capped:false,findings:[{title:'HTTP denials',hostname:'host-a',source_ip:'192.0.2.1',count:10,threshold:10,unit:'responses',evidence_ids:[1,2],explanation:'Review access denials'}],rules:[{id:'http_denials',name:'HTTP denials',description:'Review before acting',enabled:true,threshold:10}]};
else if(path.endsWith('/brief'))data={open_count:1,unassigned_count:1,affected_assets:1,resolved_count:0,scope:'Local incidents',method:'Explained priority',generated_at:'2026-10-08',queue:[{...incident,priority_score:70,reasons:['High severity: 60 points','Unassigned: +10'],next_steps:['Assign an owner']}]};
else if(path.endsWith('/insights'))data={hosts_checked:1,warming_up:[],findings:[],method:'Median baseline'};
else if(path.endsWith('/users')&&r.request().method()==='POST')data={name:'new-user',role:'viewer',api_key:'synthetic-one-time-key'};
return r.fulfill({json:data});});
await page.goto('http://127.0.0.1:8081/#incidents');await page.getByRole('button',{name:'Unlock workspace',exact:true}).click();await page.locator('#operatorKey').fill('synthetic-key');await page.locator('#dialogConfirm').click();await page.waitForSelector('[data-incident]');
assert.equal(await page.locator('#view img').count(),0);await page.locator('[data-incident]').click();await page.waitForSelector('#socEdit');assert.equal(await page.locator('#socDialog script').count(),0);
await page.locator('#incidentNote').fill('Investigated');await page.getByRole('button',{name:'Save investigation',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('#socDialog').open);
for(const view of ['detections','brief','insights','access','activity']){await page.locator(`.nav-link[data-view="${view}"]`).click();await page.waitForFunction(()=>!document.querySelector('#refreshButton').disabled);assert.equal(await page.locator('#errorBanner').isVisible(),false);}
await page.locator('.nav-link[data-view="access"]').click();await page.waitForSelector('#socName');await page.locator('#socName').fill('new-user');await page.getByRole('button',{name:'Create key',exact:true}).click();await page.waitForSelector('#newAccessKey');assert.equal(await page.locator('#newAccessKey').inputValue(),'synthetic-one-time-key');await page.locator('#socClose').click();await page.waitForSelector('#newAccessKey',{state:'detached'});assert.equal(await page.locator('#newAccessKey').count(),0);
await page.locator('.nav-link[data-view="brief"]').click();await page.waitForSelector('#downloadBrief');const download=page.waitForEvent('download');await page.locator('#downloadBrief').click();assert.equal((await download).suggestedFilename(),'operations-handover.txt');
await page.locator('.nav-link[data-view="detections"]').click();await page.waitForSelector('.detectionRule');await page.locator('.detectionRule input[type=number]').fill('15');await page.getByRole('button',{name:'Save rule',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('#refreshButton').disabled);
await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
assert.deepEqual(errors,[]);console.log('PASS: security navigation, safe evidence, investigation update, one-time key clearing, mobile layout.');
}finally{await browser.close();}})().catch(e=>{console.error(e);process.exitCode=1});