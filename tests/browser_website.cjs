const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({channel:'msedge',headless:true,args:['--disable-gpu']});
 try{
  const page=await browser.newPage({viewport:{width:1360,height:1000},reducedMotion:'reduce'});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/processes?*',r=>r.fulfill({json:Array.from({length:120},(_,i)=>({pid:i+10,name:`process-${i}`,cpu:i,memory:1,user:'test'}))}));
  await page.goto('http://127.0.0.1:8081');await page.waitForSelector('.metric-card');
  await page.keyboard.press('Control+k');await page.locator('#commandInput').fill('privacy');
  await page.locator('#commandResults [data-view="privacy"]').click();await page.waitForSelector('.prose');assert.equal(await page.locator('#commandDialog').isVisible(),false);
  await page.locator('.footer-links a[href="#help"]').click();await page.waitForSelector('.faq');await page.locator('summary').first().click();assert.equal(await page.locator('details').first().getAttribute('open'),'');
  await page.locator('.nav-link[data-view="settings"]').click();await page.waitForSelector('#preferencesForm');
  await page.locator('#prefPageSize').selectOption('25');await page.locator('#prefInterval').selectOption('30000');await page.locator('#prefTheme').selectOption('dark');await page.getByRole('button',{name:'Save preferences',exact:true}).click();assert.equal(await page.locator('html').getAttribute('data-theme'),'dark');assert.equal(await page.locator('#pollLabel').innerText(),'30s');
  await page.locator('.nav-link[data-view="processes"]').click();await page.waitForSelector('#dataTable');assert.equal(await page.locator('#dataTable tbody tr').count(),25);
  await page.getByRole('button',{name:'Next page',exact:true}).click();assert((await page.locator('#dataTable tbody tr').first().innerText()).includes('process-25'));
  await page.locator('#tableSearch').fill('process-119');assert.equal(await page.locator('#dataTable tbody tr').count(),1);
  await page.reload();await page.waitForSelector('#dataTable');assert.equal(await page.locator('#dataTable tbody tr').count(),25);assert.equal(await page.locator('html').getAttribute('data-theme'),'dark');
  await page.context().setOffline(true);await page.waitForSelector('#connectionBanner:visible');await page.context().setOffline(false);await page.waitForFunction(()=>document.querySelector('#connectionBanner').hidden);
  await page.locator('.nav-link[data-view="settings"]').click();await page.waitForSelector('#resetPreferences');await page.locator('#resetPreferences').click();await page.waitForFunction(()=>document.querySelector('#prefPageSize')?.value==='50');assert.equal(await page.locator('#prefPageSize').inputValue(),'50');
  await page.setViewportSize({width:390,height:844});assert.equal(await page.locator('#sidebar').evaluate(e=>e.inert),true);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.locator('#menuButton').click();assert.equal(await page.locator('#sidebar').evaluate(e=>e.inert),false);await page.locator('.nav-link[data-view="help"]').click();await page.waitForSelector('.faq');assert.equal(await page.locator('#sidebar').evaluate(e=>e.inert),true);
  assert.deepEqual(errors,[]);console.log('PASS: command search, Help/Privacy, preferences and persistence, pagination, filters, offline/reconnect, reset, mobile keyboard navigation.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
