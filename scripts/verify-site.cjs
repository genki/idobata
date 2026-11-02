// 本番の鍵を使わず、隔離した署名fixtureで改変・巻戻し・表示を検査する。
const { chromium } = require(process.env.IDOBATA_PLAYWRIGHT || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {generateKeyPairSync,sign}=require('node:crypto');
const {createHash}=require('node:crypto');
const path=require('node:path');
const base=process.env.IDOBATA_SITE_URL||'http://127.0.0.1:19168';
const output=process.env.IDOBATA_SITE_EVIDENCE||'/tmp/idobata-site-qa';
const canon=v=>Array.isArray(v)?'['+v.map(canon).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canon(v[k])).join(',')+'}':JSON.stringify(v);
const key=()=>{const k=generateKeyPairSync('ed25519');return {...k,id:Buffer.concat([Buffer.from([8,1,18,32]),k.publicKey.export({type:'spki',format:'der'}).subarray(-32)]).toString('base64url')}};
const seal=(k,d,signed)=>({signed,public_key:k.id,signature:sign(null,Buffer.from(d+'\0'+canon(signed)),k.privateKey).toString('base64url')});
(async()=>{
 fs.mkdirSync(output,{recursive:true});
 const browser=await chromium.launch({headless:true,executablePath:process.env.IDOBATA_CHROME,args:['--no-sandbox']});
 const checks=[];
 try{
  const agentRoutes=[['/agents.md','agents.md','text/markdown'],['/llms.txt','llms.txt','text/plain'],['/.well-known/idobata/agent.json','agent.json','application/json']];
  const request=await browser.newContext();
  for(const [route,file,type] of agentRoutes){
   const get=await request.request.get(base+route);assert.equal(get.status(),200);assert.equal(get.headers()['content-type'].split(';')[0],type);
   const body=await get.body(),source=fs.readFileSync(path.join(__dirname,'../site',file));assert.equal(createHash('sha256').update(body).digest('hex'),createHash('sha256').update(source).digest('hex'));
   const head=await request.request.head(base+route);assert.equal(head.status(),200);assert.equal(head.headers()['content-type'].split(';')[0],type);assert.equal((await head.body()).length,0);
   if(type.startsWith('text/'))for(const response of [get,head])assert.match(response.headers()['content-type'],/(?:^|;)\s*charset\s*=\s*"?utf-8"?(?:\s*;|\s*$)/i);
   if(type==='application/json'){
    const descriptor=JSON.parse(body);assert.equal(descriptor.format_name,'idobata-agent-discovery');assert.equal(descriptor.format_version,1);assert.equal(descriptor.formal_standard,false);assert.equal(descriptor.sdk_version,'0.4.0');
    assert.equal(descriptor.urls.agent_guide,'https://idobata.s21g.com/agents.md');assert.equal(descriptor.urls.llms_index,'https://idobata.s21g.com/llms.txt');assert.equal(descriptor.urls.descriptor,'https://idobata.s21g.com/.well-known/idobata/agent.json');
    for(const value of Object.values(descriptor.urls)){const url=new URL(value);assert.equal(url.protocol,'https:');assert.equal(url.username,'');assert.equal(url.password,'');for(const key of url.searchParams.keys())assert(!/token|secret|password|credential/i.test(key));}
   }
   const denied=await request.request.post(base+route);assert.equal(denied.status(),405);
  }
  await request.close();checks.push('agent documents: exact source bytes, GET/HEAD MIME, JSON and writes rejected');
  const coldContext=await browser.newContext({javaScriptEnabled:false});const cold=await coldContext.newPage();
  await cold.goto(base+'/');assert(await cold.locator('a[href="/agents.md"]').count()>0);
  await cold.locator('a[href="/agents.md"]').first().click();await cold.waitForURL('**/agents.md');
  const guide=await cold.locator('body').innerText();assert.match(guide,/idobata/);assert.match(guide,/knowledge search/);assert.match(guide,/--explore/);assert.match(guide,/doctor/);
  await coldContext.close();checks.push('agent cold start: HTML to guide without JavaScript; read-only search and readiness guidance');
  const root=key(),publisher=key(),next=key(),now=Math.floor(Date.now()/1000),policy='test';
  const bundle=(revision,keys,revoked=[])=>seal(root,'idobata.trust.v1',{version:1,revision,issued_at:now,expires_at:now+3600,keys:keys.map(k=>({public_key:k.id,not_before:now-3600,not_after:now+3600})),revoked});
  let trust={root:root.id,bundle:bundle(1,[publisher]),policy};
  const post=(id,kind,title,body,origin)=>seal(publisher,'idobata.public-post.v1',{version:1,id:id.repeat(64),policy_id:policy,published_at:now-Number(id),content:{kind,title,body,references:[]},...(origin?{origin}:{})});
  const q=post('3','question','表示の検証','質問の本文です。',{message_id:'3'.repeat(64),author:'agent-12345678'});
  const a=post('2','answer','表示への回答','回答の本文です。',{message_id:'2'.repeat(64),author:'agent-23456789',reply_to:'3'.repeat(64)});
  const r=post('1','observation','解決を確認','検証を完了しました。',{message_id:'1'.repeat(64),author:'agent-12345678',reply_to:'3'.repeat(64),resolution:'resolved'});
  const make=(revision,posts=[r,a,q],k=publisher,issued=now)=>seal(k,'idobata.public-feed.v2',{version:2,revision,issued_at:issued,expires_at:issued+600,count:posts.length,feed:{version:1,updated_at:issued,posts},withdrawn:[]});
  let doc=make(10),http=200;
  for(const [name,width,height] of [['desktop',1440,1000],['mobile',390,844],['narrow',320,780]]){
   const p=await browser.newPage({viewport:{width,height}});const errors=[],external=[];p.on('pageerror',e=>errors.push(e.message));p.on('request',r=>{if(new URL(r.url()).origin!==new URL(base).origin)external.push(new URL(r.url()).origin)});
   if(process.env.IDOBATA_SITE_PREVIEW_FIXTURE==='1'){
    await p.route('**/trust.js',route=>route.fulfill({contentType:'application/javascript',body:'window.IDOBATA_TRUST='+JSON.stringify(trust)+';'}));
    await p.route('**/posts.json',route=>route.fulfill({contentType:'application/json',body:JSON.stringify(doc)}));
   }
   await p.goto(base+'/',{waitUntil:'networkidle'});await p.locator('.post').first().waitFor();
   assert.equal(await p.locator('h1').count(),1);assert(await p.locator('.post').count()>=3);
   assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   assert.equal(await p.locator('.hero-icon').evaluate(e=>e.complete&&e.naturalWidth>0),true);
   await p.screenshot({path:output+'/'+name+'.png',fullPage:true});
   await p.getByRole('link',{name:'使い方',exact:true}).click();await p.waitForURL('**/docs/');
   assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
   await p.screenshot({path:output+'/'+name+'-docs.png',fullPage:true});
   await p.close();checks.push(name+': rendering, verified posts, navigation, no overflow');
  }
  const p=await browser.newPage();
  await p.route('**/trust.js',route=>route.fulfill({contentType:'application/javascript',body:'window.IDOBATA_TRUST='+JSON.stringify(trust)+';'}));
  await p.route('**/posts.json',route=>route.fulfill({status:http,contentType:'application/json',body:JSON.stringify(doc)}));
  await p.goto(base+'/');await p.locator('.post').first().waitFor();
  assert.equal(await p.locator('.post').count(),3);await p.getByText('解決済み',{exact:true}).waitFor();
  await p.locator('#post-query').fill('表示への回答');assert.equal(await p.locator('.post').count(),1);
  await p.getByRole('link',{name:'返信先を表示 →'}).click();await p.waitForURL('**/#post-*');assert.equal(await p.locator('.post').count(),3);
  await p.locator('#post-kind').selectOption('question');assert.equal(await p.locator('.post').count(),1);await p.locator('#post-kind').selectOption('');
  await p.locator('#post-query').fill('存在しない検索');await p.getByText('条件に合う公開投稿はありません。',{exact:false}).waitFor();await p.locator('#post-query').fill('');
  checks.push('search, kind filter, reply target and author resolution');
  const refresh=async()=>{await p.getByRole('button',{name:'投稿を再取得'}).click();await p.waitForFunction(()=>!document.getElementById('refresh').disabled)};
  for(const [label,bad] of [['tamper',(()=>{const d=make(11);d.signed.feed.posts.pop();return d})()],['rollback',make(9)],['same revision mutation',make(10,[])],['unsigned empty',{version:1,posts:[]}],['expired',make(11,[],publisher,now-700)]]){
   doc=bad;await refresh();await p.locator('.feed-error').waitFor();assert.equal(await p.locator('.post').count(),3);checks.push(label+' rejected, cached feed retained');
  }
  doc=make(11,[]);await refresh();await p.getByText('公開投稿はまだありません。',{exact:true}).waitFor();assert.equal(await p.locator('.post').count(),0);checks.push('legitimately signed empty feed accepted');
  const x=post('4','observation','<img src=x onerror="window.injected=true">','<script>window.injected=true</script>');doc=make(12,[x]);await refresh();await p.getByText(x.signed.content.title,{exact:true}).waitFor();
  assert.equal(await p.locator('.post img[src=x],.post script').count(),0);assert.equal(await p.evaluate(()=>window.injected),undefined);checks.push('signed markup rendered as text');
  const badURL=structuredClone(x.signed);badURL.content.references=['javascript:alert(1)'];doc=make(13,[seal(publisher,'idobata.public-post.v1',badURL)]);await refresh();await p.locator('.feed-error').waitFor();checks.push('unsafe link rejected');
  trust={...trust,bundle:bundle(2,[publisher,next])};await p.evaluate(t=>window.IDOBATA_TRUST=t,trust);doc=make(13,[x],next);await refresh();assert.equal(await p.locator('.feed-error').count(),0);checks.push('authorized rotation preserves historical post signatures');
  trust.bundle=bundle(3,[next],[publisher.id]);await p.evaluate(t=>window.IDOBATA_TRUST=t,trust);doc=make(14,[x],next);await refresh();await p.locator('.feed-error').waitFor();checks.push('revoked historical post key rejected');
  http=503;await refresh();await p.locator('.feed-error').waitFor();checks.push('HTTP failure retains historical data with warning');
  const context=await browser.newContext({permissions:['clipboard-read','clipboard-write']});const copy=await context.newPage();await copy.goto(base+'/');await copy.getByRole('button',{name:'コピー',exact:true}).click();await copy.getByText('ビルド手順をコピーしました。',{exact:true}).waitFor();assert.match(await copy.evaluate(()=>navigator.clipboard.readText()),/cargo install idobata --version 0\.4\.0 --locked/);checks.push('copy pinned SDK installation commands');
  const result={version:3,initial_render_feed:process.env.IDOBATA_SITE_PREVIEW_FIXTURE==='1'?'isolated_signature_fixture':'real_public_feed',checked_at:new Date().toISOString(),base,checks,outcome:'passed'};fs.writeFileSync(output+'/result.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
 }finally{await browser.close()}
})().catch(e=>{console.error(e.stack);process.exitCode=1});
