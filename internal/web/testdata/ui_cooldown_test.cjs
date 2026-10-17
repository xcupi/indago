const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function harness(responses) {
  let now = Date.parse('2026-10-17T08:00:00Z');
  const timers = [], calls = [], nodes = new Map();
  function node() { return {textContent:'',className:'',classList:{add(){},remove(){},toggle(){}},setAttribute(){},append(){},appendChild(){},replaceChildren(){},addEventListener(){}}; }
  for(const id of ['error','apiStatus','projectSelect']) nodes.set(id,node());
  const storage = new Map();
  class ClockDate extends Date { static now() {return now;} }
  const c = vm.createContext({console, Response, Headers, URL, Blob, Date:ClockDate,
    setTimeout(fn,ms){assert.ok(Number.isFinite(ms)&&ms>=0&&ms<=60000, 'bounded timer');timers.push({at:now+ms,fn});return timers.length;},
    clearTimeout(){},setInterval(){},clearInterval(){},
    sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    localStorage:{getItem(){return null;}},
    document:{getElementById:id=>nodes.get(id),addEventListener(){},createElement:node},
    window:{prompt(){throw Error('unexpected prompt');}},location:{hash:'#/dashboard'},
    fetch:async (url,opts)=>{calls.push({url,opts,at:now});return responses.shift()();}
  });
  vm.runInContext(fs.readFileSync(__dirname+'/../assets/app.js','utf8'),c);
  async function flush(){for(let i=0;i<30;i++)await Promise.resolve();}
  return {c,calls,nodes,run:s=>vm.runInContext(s,c),flush,
    async tick(ms){now+=ms;let due;do {due=timers.filter(t=>t.at<=now);for(const t of due){timers.splice(timers.indexOf(t),1);t.fn();}await flush();}while(timers.some(t=>t.at<=now));}};
}
function response(status,header,body='{}'){return ()=>new Response(body,{status,headers:header===undefined?{}:{'Retry-After':header}});}

for (const [header,wait] of [[undefined,2000],['nonsense',2000],['-5',2000],['NaN',2000],['1.5',2000],['0',1000],['9999999',60000],['Sat, 17 Oct 2026 07:59:00 GMT',2000]]) {
 test('bounded header '+header,async()=>{
  const h=harness([response(429,header),response(200)]);
  const done=h.run(`getJSON('/api/bounds')`);await h.flush();
  await h.tick(wait-1);assert.equal(h.calls.length,1);
  await h.tick(1);await done;assert.equal(h.calls.length,2);
 });
}

test('repeated 429 has finite read retries and a safe Refresh error',async()=>{
 const h=harness(Array.from({length:4},()=>response(429,'1','{"error":"dummy-server-secret"}')));
 const result=h.run(`getJSON('/api/repeated')`);result.catch(()=>{});await h.flush();
 await h.tick(1000);await h.tick(1000);
 await assert.rejects(result,/Refresh/);assert.equal(h.calls.length,3);
 await h.tick(60000);assert.equal(h.calls.length,3);
 assert.doesNotMatch(h.nodes.get('apiStatus').textContent,/dummy/);
});

test('ordinary auth headers, CSRF, request body and HEAD stay unchanged',async()=>{
 const h=harness([response(200,undefined,'{"ok":true}'),response(201),()=>new Response(null,{status:200})]);
 h.run(`storeToken('dummy-token-not-rendered');`);
 await h.run(`getJSON('/api/normal')`);
 await h.run(`mutate('POST','/api/projects',{name:'ordinary'})`);
 await h.run(`authedFetch('/api/head',{method:'HEAD'})`);
 assert.equal(h.calls.length,3);
 assert.equal(h.calls[0].opts.headers.Authorization,'Bearer dummy-token-not-rendered');
 assert.equal(h.calls[1].opts.headers['X-Indago-Client'],'ui');
 assert.equal(h.calls[1].opts.headers['Content-Type'],'application/json');
 assert.equal(h.calls[1].opts.body,'{"name":"ordinary"}');
 assert.equal(h.calls[2].opts.method,'HEAD');
});

test('401 token prompt and subsequent 429 cooldown preserve session token',async()=>{
 const h=harness([response(401),response(429,'1'),response(200)]);
 let prompts=0;h.c.window.prompt=()=>{prompts++;return 'dummy-prompt-token';};
 const result=h.run(`getJSON('/api/token')`);await h.flush();
 assert.equal(prompts,1);assert.equal(h.calls.length,2);
 await h.tick(1000);await result;
 assert.equal(h.calls.length,3);assert.equal(h.calls[2].opts.headers.Authorization,'Bearer dummy-prompt-token');
 assert.equal(h.run('storedToken()'),'dummy-prompt-token');
 assert.doesNotMatch(h.nodes.get('apiStatus').textContent,/dummy/);
});

test('HEAD retries safely after cooldown',async()=>{
 const h=harness([response(429,'1'),()=>new Response(null,{status:200})]);
 const result=h.run(`authedFetch('/api/head',{method:'HEAD'})`);await h.flush();
 await h.tick(1000);assert.equal((await result).status,200);assert.equal(h.calls.length,2);
});

test('navigation during JSON body read discards the old data',async()=>{
 let release;
 const h=harness([()=>({status:200,ok:true,json:()=>new Promise(r=>release=r)})]);
 const result=h.run(`getJSON('/api/delayed-body')`);result.catch(()=>{});await h.flush();
 h.run(`currentView = {name:'new'};`);release({stale:true});
 await assert.rejects(result,/navigation/);
});

test('project refresh failure keeps the selected project',async()=>{
 const h=harness([response(500)]);
 h.run(`ctx.projects=[{id:'kept',name:'Kept'}];ctx.projectId='kept';`);
 await h.run(`loadProjects()`);
 assert.equal(h.run('ctx.projectId'),'kept');
 assert.equal(h.run('ctx.projects.length'),1);
});

test('new route does not reuse an obsolete pending read',async()=>{
 let release;
 const h=harness([()=>new Promise(r=>release=r),response(200,undefined,'{"fresh":true}')]);
 const old=h.run(`getJSON('/api/shared-route')`);old.catch(()=>{});await h.flush();
 h.run(`currentView = {name:'new'};`);
 const fresh=h.run(`getJSON('/api/shared-route')`);fresh.catch(()=>{});await h.flush();
 assert.equal(h.calls.length,2);
 assert.deepEqual(await fresh,{fresh:true});
 release(new Response('{}',{status:200}));await assert.rejects(old,/navigation/);
});

test('obsolete route stops retrying and rejects late data',async()=>{
 const h=harness([response(429,'2'),response(200)]);
 const result=h.run(`getJSON('/api/old')`);result.catch(()=>{});await h.flush();
 h.run(`currentView = {name:'new'};`);
 await h.tick(2000);
 assert.equal(h.calls.length,1);
 await assert.rejects(result,/navigation/i);
});

test('overlapping JSON refreshes coalesce during cooldown',async()=>{
 const h=harness([response(429,'2'),response(200,undefined,'{"ok":true}')]);
 const results=Array.from({length:50},()=>h.run(`getJSON('/api/shared')`));
 for(const r of results)r.catch(()=>{});
 await h.flush();assert.equal(h.calls.length,1);
 await h.tick(2000);assert.equal(h.calls.length,2);await Promise.all(results);
});

test('POST is sent once and reports a safe actionable throttle error',async()=>{
 const h=harness([response(429,'2','{"error":"dummy-server-secret"}')]);
 const result=await h.run(`mutate('POST','/api/projects',{name:'dummy-body-secret'})`);
 assert.equal(h.calls.length,1);assert.equal(result.status,429);
 assert.match(result.data.error,/wait.*try again/i);
 assert.doesNotMatch(result.data.error,/dummy/);
 const second=await h.run(`mutate('POST','/api/projects',{})`);
 assert.equal(second.status,429);assert.equal(h.calls.length,1);
 await h.tick(10000);assert.equal(h.calls.length,1);
});

test('HTTP-date Retry-After waits until the date',async()=>{
 const h=harness([response(429,'Sat, 17 Oct 2026 08:00:05 GMT'),response(200)]);
 const result=h.run(`getJSON('/api/date')`);await h.flush();
 await h.tick(4999);assert.equal(h.calls.length,1);
 await h.tick(1);await result;assert.equal(h.calls[1].at-h.calls[0].at,5000);
});

test('GET waits for numeric Retry-After then recovers',async()=>{
 const h=harness([response(429,'2'),response(200,undefined,'{"recovered":true}')]);
 const result=h.run(`getJSON('/api/example')`);result.catch(()=>{});await h.flush();
 assert.equal(h.calls.length,1);
 assert.match(h.nodes.get('apiStatus').textContent,/throttl|waiting/i);
 await h.tick(1999);assert.equal(h.calls.length,1);
 await h.tick(1);assert.equal(h.calls.length,2);assert.deepEqual(await result,{recovered:true});
 assert.equal(h.nodes.get('apiStatus').textContent,'');
});
