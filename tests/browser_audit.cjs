// Optional browser regression suite: install playwright or expose it through NODE_PATH.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({channel:process.env.OPS_BROWSER||'msedge',headless:true,args:['--disable-gpu']});
 try{
  const page=await browser.newPage({viewport:{width:1280,height:900},reducedMotion:'reduce'});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/servers',r=>r.fulfill({json:{servers:['host-a','host-b'],local_hostname:'host-a'}}));
  await page.route('**/api/processes?*',r=>r.fulfill(r.request().url().includes('hostname=host-b')?{status:503,json:{detail:'Host unavailable'}}:{json:[{pid:42,name:'<img src=x onerror="window.injected=true">',cpu:5,memory:2,user:'operator'}]}));
  await page.goto('http://127.0.0.1:8081/#processes');await page.waitForSelector('[data-kill]');
  assert.equal(await page.locator('[data-kill]').getAttribute('data-process-host'),'host-a');
  assert.equal(await page.locator('#rows img').count(),0);
  await page.locator('#hostSelect').selectOption('host-b');
  assert.equal(await page.locator('[data-kill]').count(),0);
  await page.waitForSelector('#errorBanner:visible');
  assert.equal(await page.locator('[data-kill]').count(),0);
  await page.locator('#exportButton').click();
  assert.equal(await page.locator('#toast').innerText(),'No records to export yet');
  // An old response arriving after a server change must not repopulate rows.
  await page.unroute('**/api/processes?*');
  let release,started;
  const incoming=new Promise(resolve=>started=resolve);
  const gate=new Promise(resolve=>release=resolve);
  await page.route('**/api/processes?*',async r=>{
   if(r.request().url().includes('hostname=host-a')){started();await gate;await r.fulfill({json:[{pid:99,name:'old-host-only',cpu:1,memory:1}]});}
   else await r.fulfill({status:503,json:{detail:'Still unavailable'}});
  });
  await page.locator('#hostSelect').selectOption('host-a');await incoming;
  await page.locator('#hostSelect').selectOption('host-b');release();
  await page.waitForFunction(()=>!document.querySelector('#refreshButton').disabled);
  assert.equal(await page.locator('[data-kill]').count(),0);
  assert(!(await page.locator('#view').innerText()).includes('old-host-only'));
  assert.deepEqual(errors,[]);
  console.log('PASS: host-bound actions, failed-host isolation, stale-response rejection, safe exports, HTML escaping.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
