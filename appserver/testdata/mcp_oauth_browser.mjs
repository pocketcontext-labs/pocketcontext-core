#!/usr/bin/env node
// Synthetic opt-in browser fixture; no external OAuth providers or real data.
import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const {chromium}=createRequire(process.env.CORE_PLAYWRIGHT_PACKAGE_JSON)('playwright');
const origin='https://knowledge.example.com';
const signIn=process.env.POCKETCONTEXT_SYNTHETIC_SIGNIN,port=process.env.POCKETCONTEXT_SYNTHETIC_PORT;
assert(signIn?.startsWith(origin+'/bundle/login#') && /^\d+$/.test(port));
const browser=await chromium.launch({args:['--no-proxy-server',`--host-resolver-rules=MAP knowledge.example.com 127.0.0.1:${port}`]});
const context=await browser.newContext({viewport:{width:390,height:844},ignoreHTTPSErrors:true});
const problems=[];
await context.route('**/*',async route=>{
 const u=new URL(route.request().url());
 if(u.origin===origin) await route.continue();
 else if(u.origin==='https://client.example.com' && u.pathname==='/callback') await route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Synthetic callback</title>'});
 else {problems.push('unexpected external request');await route.abort()}
});
try{
 const reader=await context.newPage();reader.on('pageerror',e=>problems.push(e.message));
 await reader.goto(origin+'/oauth/connections');
 await reader.getByText('Sign in to the reader in this browser first, then return here.',{exact:true}).waitFor();
 const call=async(path,body,token='',form=false)=>reader.evaluate(async({path,body,token,form})=>{
  const response=await fetch(path,{method:'POST',headers:{'Content-Type':form?'application/x-www-form-urlencoded':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:form?new URLSearchParams(body).toString():JSON.stringify(body)});
  return {status:response.status,data:await response.json()};
 },{path,body,token,form});
 const registered=await call('/oauth/register',{client_name:'Synthetic <script>bad()</script> client',redirect_uris:['https://first.example.com/callback','https://client.example.com/callback'],token_endpoint_auth_method:'none'});
 assert.equal(registered.status,201);
 const verifier=randomBytes(32).toString('base64url');const client=registered.data.client_id;
 const params=new URLSearchParams({client_id:client,redirect_uri:'https://client.example.com/callback',response_type:'code',code_challenge_method:'S256',code_challenge:createHash('sha256').update(verifier).digest('base64url'),resource:origin+'/mcp',scope:'knowledge',state:'synthetic-state'});
 const consent=await context.newPage();consent.on('pageerror',e=>problems.push(e.message));
 await consent.goto(origin+'/oauth/authorize?'+params);
 await consent.getByText('Registered callback: https://client.example.com/callback',{exact:true}).waitFor();
 assert.equal(await consent.locator('script').count(),1);
 for(const width of [390,320]){await consent.setViewportSize({width,height:844});assert(await consent.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'consent must fit mobile width')}
 await consent.setViewportSize({width:390,height:844});
 await consent.getByRole('button',{name:'Allow access',exact:true}).click();
 await consent.getByText('Sign in to the reader in this browser first, then return here.',{exact:true}).waitFor();
 // The browser never learns or enters the synthetic account's password.
 await reader.goto(signIn);await reader.waitForURL(origin+'/');
 await consent.getByRole('button',{name:'Allow access',exact:true}).click();
 await consent.waitForURL('https://client.example.com/callback?**');
 const callback=new URL(consent.url());assert.equal(callback.searchParams.get('state'),'synthetic-state');
 const tokens=await call('/oauth/token',{grant_type:'authorization_code',client_id:client,code:callback.searchParams.get('code'),redirect_uri:'https://client.example.com/callback',code_verifier:verifier,resource:origin+'/mcp'},'',true);
 assert.equal(tokens.status,200);
 assert.equal((await call('/mcp',{},tokens.data.access_token)).status,200);
 await reader.goto(origin+'/oauth/connections');
 await reader.getByRole('button',{name:'Revoke access',exact:true}).click();
 await reader.getByText('Access revoked.',{exact:true}).waitFor();
 assert.equal((await call('/mcp',{},tokens.data.access_token)).status,401);
 assert.equal((await call('/oauth/token',{grant_type:'refresh_token',client_id:client,refresh_token:tokens.data.refresh_token,resource:origin+'/mcp'},'',true)).status,400);
 // Capture Chromium's native-scheme navigation request. No OS handler is
 // installed by this fixture; native-client receipt remains a manual check.
 for(const redirect of ['com.example.app:/oauth/callback','cursor://anysphere.cursor-mcp/oauth/callback']){
  const registeredNative=await call('/oauth/register',{client_name:'Synthetic native client',redirect_uris:[redirect],token_endpoint_auth_method:'none'});
  assert.equal(registeredNative.status,201);
  const nativeVerifier=randomBytes(32).toString('base64url');
  const nativeParams=new URLSearchParams({client_id:registeredNative.data.client_id,redirect_uri:redirect,response_type:'code',code_challenge_method:'S256',code_challenge:createHash('sha256').update(nativeVerifier).digest('base64url'),scope:'knowledge',state:'native-state'});
  const native=await context.newPage();native.on('pageerror',e=>problems.push(e.message));
  await native.goto(origin+'/oauth/authorize?'+nativeParams);
  await native.getByText('Registered callback: '+redirect,{exact:true}).waitFor();
  const cdp=await context.newCDPSession(native);await cdp.send('Page.enable');
  let timer;
  const requested=new Promise((resolve,reject)=>{
   timer=setTimeout(()=>reject(new Error('native callback navigation was not requested')),10000);
   cdp.on('Page.frameRequestedNavigation',event=>{
    if(event.url.startsWith(redirect+'?')){clearTimeout(timer);resolve(event.url)}
   });
  });
  let nativeURL;
  try{await native.getByRole('button',{name:'Allow access',exact:true}).click();nativeURL=new URL(await requested)}
  finally{clearTimeout(timer);await cdp.detach();await native.close()}
  assert.equal(nativeURL.searchParams.get('state'),'native-state');
  assert(nativeURL.searchParams.get('code'));
  const nativeTokens=await call('/oauth/token',{grant_type:'authorization_code',client_id:registeredNative.data.client_id,code:nativeURL.searchParams.get('code'),redirect_uri:redirect,code_verifier:nativeVerifier},'',true);
  assert.equal(nativeTokens.status,200);
  assert.equal((await call('/mcp',{},nativeTokens.data.access_token)).status,200);
 }
 assert.deepEqual(problems,[]);
 console.log('ok - reader link login without password, consent retry, escaped client name, exact callback, OAuth exchange, authenticated MCP, browser revocation, private-scheme consent navigation');
}finally{await context.close();await browser.close()}
