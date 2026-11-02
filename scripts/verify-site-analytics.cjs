// Uses the real public gtag SDK, but intercepts ALL browser requests to Google.
// No collect hit leaves the disposable browser. Never use an existing browser.
const { chromium } = require(process.env.IDOBATA_PLAYWRIGHT || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const base = process.env.IDOBATA_SITE_URL || 'http://127.0.0.1:19168';
const origin = new URL(base).origin;
const id = 'G-Y6E4X6V45B';
const sentinel = 'IDOBATA_PRIVATE_SENTINEL_NEVER_SEND';
const out = process.env.IDOBATA_ANALYTICS_EVIDENCE || '/tmp/idobata-analytics-qa';
const decode = text => { for (let i=0;i<3;i++) { try { text=decodeURIComponent(text); } catch { break; } } return text; };
const wait = ms => new Promise(resolve=>setTimeout(resolve,ms));
function events(requests) {
 return requests.flatMap(r=>(r.body?r.body.split(/\r?\n/):['']).map(line=>{
  const value=new URL(r.url).searchParams;
  for(const [k,v] of new URLSearchParams(line))value.set(k,v);
  return value;
 })).filter(p=>p.has('en'));
}
(async()=>{
 fs.mkdirSync(out,{recursive:true});
 // Only this public script is fetched outside the browser, with no cookies or referrer.
 const sdk=process.env.IDOBATA_GTAG_SOURCE?fs.readFileSync(process.env.IDOBATA_GTAG_SOURCE,'utf8'):
  await fetch('https://www.googletagmanager.com/gtag/js?id='+id,{signal:AbortSignal.timeout(20000)}).then(r=>{assert.equal(r.status,200);return r.text()});
 const browser=await chromium.launch({headless:true,executablePath:process.env.IDOBATA_CHROME,args:['--no-sandbox']});
 const checks=[];
 async function fixture({suffix='',referrer='',preload='',emptyId=false,pagePath='/'}={},check){
  const context=await browser.newContext({extraHTTPHeaders:{'X-Idobata-Diagnostic':'1'}});
  const requests=[],loaders=[],errors=[],violations=[];
  await context.exposeBinding('__idobataAnalyticsCspCheck',(_source,value)=>violations.push(value));
  await context.addInitScript(({referrer,preload})=>{
   if(window===parent&&referrer)Object.defineProperty(document,'referrer',{value:referrer});
   if(preload==='dnt')Object.defineProperty(navigator,'doNotTrack',{value:'1'});
   if(preload==='gpc')Object.defineProperty(navigator,'globalPrivacyControl',{value:true});
   if(preload==='session')sessionStorage.setItem('idobata-analytics-disabled','1');
   if(preload==='storage')Object.defineProperty(window,'sessionStorage',{get(){throw new Error('fixture_storage_blocked')}});
   document.addEventListener('securitypolicyviolation',e=>{
    // Chrome's plain-text/Markdown viewer adds its own inline <pre> style.
    // Check our HTML and sender documents, not that unrelated built-in viewer.
    if(['/', '/docs/', '/analytics-frame.html'].includes(location.pathname))
     window.__idobataAnalyticsCspCheck({directive:e.effectiveDirective,blocked:e.blockedURI});
   });
  },{referrer,preload});
  await context.route('**/*',async route=>{
   const request=route.request(),u=new URL(request.url());
   if(u.origin===origin){
    if(u.pathname==='/'||u.pathname==='/docs/'){
     const response=await route.fetch();let body=await response.text();
     body=body.replace(/<title>.*?<\/title>/,'<title>'+sentinel+'</title>');
     if(emptyId)body=body.replace('content="'+id+'"','content=""');
     await route.fulfill({response,body});return;
    }
    await route.continue();return;
   }
   if(u.hostname==='www.googletagmanager.com'&&u.pathname==='/gtag/js'){
    loaders.push({url:request.url(),headers:request.headers()});
    await route.fulfill({contentType:'application/javascript',body:sdk});return;
   }
   requests.push({url:request.url(),body:request.postData()||'',headers:request.headers()});
   // A synthetic success avoids SDK fallback retries, still with zero real hits.
   await route.fulfill({status:204,body:''});
  });
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
  try{
   const response=await page.goto(base+pagePath+suffix,{waitUntil:'networkidle'});
   if(process.env.IDOBATA_ANALYTICS_REQUIRE_CSP==='1'){
    const policy=response.headers()['content-security-policy']||'';
    assert.match(policy,/frame-src 'self'/);assert(!/googletagmanager/.test(policy));
   }
   await check({page,context,requests,loaders});
   for(const r of [...requests,...loaders])assert(!decode(JSON.stringify(r)).includes(sentinel),'private sentinel leaked to Google request');
   assert.deepEqual(violations,[],'CSP blocked a required analytics asset or transport');
   assert.deepEqual(errors,[],'browser script error');
  }finally{await context.close()}
 }
 try{
  await fixture({suffix:'?q='+sentinel+'&utm_source='+sentinel+'#'+sentinel,referrer:'https://private.invalid/'+sentinel+'?q='+sentinel},async({page,requests,loaders})=>{
   await page.waitForFunction(id=>Boolean(document.querySelector('[data-idobata-analytics-sender]')?.contentWindow.google_tag_manager?.[id]),id);
   assert.equal(await page.evaluate(()=>typeof window.gtag),'undefined');
   await page.locator('#post-query').fill(sentinel);
   await page.evaluate(value=>{
    history.pushState({},'', '?q='+value+'&utm_campaign='+value+'#'+value);
    const node=document.createElement('button');node.dataset.analyticsDestination=value;node.textContent=value;document.body.append(node);node.click();node.remove();
   },sentinel);
   await page.locator('#copy-install').click();
   // Exercise the other fixed destinations without actually leaving this
   // fixture. A separate case below performs a real same-tab navigation.
   await page.evaluate(()=>document.addEventListener('click',event=>{
    if(event.target.closest?.('[data-analytics-destination]'))event.preventDefault();
   },{capture:true}));
   for(const destination of ['agent_guide','llms_index','agent_descriptor','participation_question','repository','release']){
    await page.locator('[data-analytics-destination="'+destination+'"]').first().click();
   }
   await page.evaluate(value=>document.querySelector('[data-idobata-analytics-sender]').contentWindow.postMessage({
    type:'idobata-analytics-event',version:1,event:'navigation_click',destination:'agent_guide',page_location:value
   },location.origin),sentinel);
   await wait(6000);
   const hits=events(requests),views=hits.filter(p=>p.get('en')==='page_view');
   assert.equal(views.length,1);assert.equal(views[0].get('dl'),'https://idobata.s21g.com/');
   assert.equal(views[0].get('ep.source_category'),'other');assert.equal(views[0].get('ep.page_kind'),'home');
   assert(!views[0].get('dr'));
   assert(hits.some(p=>p.get('en')==='navigation_click'&&p.get('ep.destination')==='copy_install'));
   for(const destination of ['agent_guide','llms_index','agent_descriptor','participation_question','repository','release']){
    assert.equal(hits.filter(p=>p.get('en')==='navigation_click'&&p.get('ep.destination')===destination).length,1,'missing/extra fixed click '+destination);
   }
   assert(!hits.some(p=>p.get('en')==='view_search_results'));
   for(const p of hits){assert(!/[?#]/.test(p.get('dl')||''));assert(!/[?#]/.test(p.get('dr')||''));assert(![...p.keys()].some(k=>k.endsWith('navigation_id')));}
   assert.equal(loaders.length,1);checks.push('real SDK: fixed canonical page/context/copy label; parent search/title/query/hash/UTM/unknown referrer excluded');
   await page.locator('[data-analytics-disable]').click();const count=requests.length;
   await page.locator('#copy-install').click();await wait(1200);assert.equal(requests.length,count);
   assert.equal(await page.locator('[data-idobata-analytics-sender]').count(),0);
   await page.reload();await wait(300);assert.equal(loaders.length,1);checks.push('stop button tears down sender and persists session opt-out');
  });
  await fixture({pagePath:'/docs/',referrer:'https://www.google.co.jp/search?q='+sentinel},async({page,requests})=>{
   await page.waitForFunction(id=>Boolean(document.querySelector('[data-idobata-analytics-sender]')?.contentWindow.google_tag_manager?.[id]),id);
   await wait(6000);const view=events(requests).find(p=>p.get('en')==='page_view');
   assert(view);assert.equal(view.get('dl'),'https://idobata.s21g.com/docs/');assert.equal(view.get('dr'),'https://www.google.com/');
   assert.equal(view.get('ep.source_category'),'google');assert.equal(view.get('ep.page_kind'),'docs');checks.push('known public referrer maps to canonical origin and fixed source category');
  });
  for(let attempt=0;attempt<3;attempt++)await fixture({},async({page,requests})=>{
   await page.waitForFunction(id=>Boolean(document.querySelector('[data-idobata-analytics-sender]')?.contentWindow.google_tag_manager?.[id]),id);
   await page.locator('a[href="/agents.md"]').first().click();await page.waitForURL('**/agents.md');await wait(1200);
   assert(events(requests).some(p=>p.get('en')==='navigation_click'&&p.get('ep.destination')==='agent_guide'),'same-tab click was lost before navigation');
   checks.push('real same-tab guide navigation preserves fixed click event ('+(attempt+1)+'/3)');
  });
  for(const [name,settings]of [['query',{suffix:'?analytics=off&q='+sentinel}],['session',{preload:'session'}],['DNT',{preload:'dnt'}],['GPC',{preload:'gpc'}],['storage blocked',{preload:'storage'}],['empty ID',{emptyId:true}]]){
   await fixture(settings,async({page,requests,loaders})=>{
    assert.equal(await page.locator('[data-idobata-analytics-sender]').count(),0);assert.equal(loaders.length,0);assert.equal(requests.length,0);
   });checks.push(name+': no sender, Google loader or analytics request');
  }
  const result={version:1,outcome:'passed',checked_at:new Date().toISOString(),base,measurement_id:id,gtag_sha256:createHash('sha256').update(sdk).digest('hex'),all_collector_requests_intercepted:true,real_collector_hits_sent:0,checks};
  fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
 }finally{await browser.close()}
})().catch(error=>{console.error(error.stack);process.exitCode=1});
