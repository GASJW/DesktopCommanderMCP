import path from 'node:path';
import { spawn } from 'node:child_process';
import { realpathSync, statSync, lstatSync } from 'node:fs';

// Nonproduction, single-process read-only MCP adapter.
// The caller must authenticate device transport and owner/tool policy separately.
const MAX_LINE=256*1024, MAX_PENDING=1;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export class LocalMcpError extends Error {
  constructor(code,message){ super(message); this.name='LocalMcpError'; this.code=code; }
}
const err=(code,message)=>new LocalMcpError(code,message);
function checkedRoot(directory){
  if(typeof directory!=='string'||!path.isAbsolute(directory))throw err('POLICY','Absolute allowed root required');
  if(lstatSync(directory).isSymbolicLink())throw err('POLICY','Symlink root forbidden');
  const root=realpathSync(directory);
  if(!statSync(root).isDirectory())throw err('POLICY','Allowed root must be a directory');
  return root;
}
function checkedRead(args,root,maxBytes){
  if(!args || Object.getPrototypeOf(args)!==Object.prototype ||
    Object.keys(args).some(x=>!['path','offset','length'].includes(x)) ||
    typeof args.path!=='string'||!path.isAbsolute(args.path)||args.path.includes('\0')) {
    throw err('DENIED','Only absolute read_file paths and bounded pagination allowed');
  }
  const offset=args.offset??0,length=args.length??100;
  if(!Number.isSafeInteger(offset)||offset<0||offset>100_000||
     !Number.isSafeInteger(length)||length<1||length>1000)throw err('DENIED','Invalid pagination');
  let target,st;
  try{
    target=realpathSync(args.path);
    st=statSync(target);
  }catch{throw err('DENIED','Target unavailable');}
  const rel=path.relative(root,target);
  if(!rel||rel==='..'||rel.startsWith('..'+path.sep)||path.isAbsolute(rel) ||
    !st.isFile() || st.size>maxBytes)throw err('DENIED','Target outside approved read-only scope');
  return {path:target,offset,length};
}
export function createLocalReadonlyMcp({
  allowedRoot,entrypoint,nodeBin=process.execPath,
  timeoutMs=8000,maxFileBytes=64*1024,
}={}){
  if(typeof process.getuid==='function' && process.getuid()===0){
    throw err('PRIVILEGE','Agent must run as nonroot');
  }
  if(typeof entrypoint!=='string'||!path.isAbsolute(entrypoint)||
     !statSync(entrypoint).isFile()||typeof nodeBin!=='string'||!path.isAbsolute(nodeBin)||
     !Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>30000||
     !Number.isSafeInteger(maxFileBytes)||maxFileBytes<1024||maxFileBytes>1024*1024){
    throw err('POLICY','Invalid local MCP runtime configuration');
  }
  const root=checkedRoot(allowedRoot);
  let child=null,started=false,dead=false,serial=0;
  const pending=new Map();
  function shutdown(error=err('UNAVAILABLE','Local MCP offline')){
    if(dead)return;
    dead=true;
    for(const [id,p] of pending){clearTimeout(p.timer);p.reject(error);}
    pending.clear();
    child?.kill('SIGTERM');
  }
  function send(method,params={},notify=false){
    if(dead||!child?.stdin?.writable) return Promise.reject(err('UNAVAILABLE','Local MCP unavailable'));
    if(pending.size>=MAX_PENDING&&!notify) return Promise.reject(err('BUSY','Local MCP busy'));
    const id='g7-agent-'+(++serial);
    const message=notify?{jsonrpc:'2.0',method,params}:{jsonrpc:'2.0',id,method,params};
    const wire=JSON.stringify(message)+'\n';
    if(Buffer.byteLength(wire)>MAX_LINE)return Promise.reject(err('DENIED','Request too large'));
    if(notify){
      child.stdin.write(wire);
      return Promise.resolve(null);
    }
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{
        pending.delete(id);
        shutdown(err('AMBIGUOUS_TIMEOUT','MCP operation timed out; no automatic replay'));
        reject(err('AMBIGUOUS_TIMEOUT','MCP operation timed out; no automatic replay'));
      },timeoutMs);
      pending.set(id,{resolve,reject,timer});
      child.stdin.write(wire,error=>{
        if(!error)return;
        const item=pending.get(id);
        if(item){clearTimeout(item.timer);pending.delete(id);item.reject(err('UNAVAILABLE','MCP pipe failure'));}
        shutdown();
      });
    });
  }
  async function start(){
    if(started)throw err('STATE','Already started');
    started=true;
    const env={};
    for(const k of ['PATH','HOME','USER','LOGNAME','TMPDIR','TMP','TEMP','USERPROFILE',
       'APPDATA','LOCALAPPDATA','SystemRoot','WINDIR','COMSPEC']){
      if(typeof process.env[k]==='string')env[k]=process.env[k];
    }
    env.DC_REMOTE_DEVICE='true';
    env.VPS_COMMANDER_DISABLE_BROWSER_INIT='1';
    child=spawn(nodeBin,[entrypoint,'--no-onboarding'],{
      cwd:path.dirname(entrypoint),shell:false,stdio:['pipe','pipe','pipe'],env,
      windowsHide:true,
    });
    let parts=[],bytes=0;
    child.stdout.on('data',chunk=>{
      let cursor=0;
      while(cursor<chunk.length&&!dead){
        const end=chunk.indexOf(10,cursor);
        const boundary=end<0?chunk.length:end;
        const part=chunk.subarray(cursor,boundary);
        bytes+=part.length;
        if(bytes>MAX_LINE){shutdown(err('UNAVAILABLE','Oversize MCP response'));return;}
        if(part.length)parts.push(part);
        if(end<0)break;
        const line=Buffer.concat(parts,bytes).toString('utf8');
        parts=[];bytes=0;
        let msg;
        try{msg=JSON.parse(line);}catch{shutdown(err('UNAVAILABLE','Malformed MCP response'));return;}
        if(msg && Object.hasOwn(msg,'id')){
          const key=String(msg.id),item=pending.get(key);
          if(item){clearTimeout(item.timer);pending.delete(key);item.resolve(msg);}
        }
        cursor=end+1;
      }
    });
    // Never forward child diagnostics to Gateway or store secret-bearing stderr.
    child.stderr.on('data',()=>{});
    child.once('error',()=>shutdown());
    child.once('exit',()=>shutdown());
    try{
      const init=await send('initialize',{
        protocolVersion:'2025-03-26',capabilities:{},
        clientInfo:{name:'vpsc-readonly-device-agent',version:'0.0.0-dev'},
      });
      if(init.error||!init.result?.capabilities)throw err('UNAVAILABLE','MCP initialization failed');
      await send('notifications/initialized',{},true);
    }catch(e){shutdown();throw e;}
    return Object.freeze({running:true,mode:'read_file_only'});
  }
  async function handle(frame){
    if(!started||dead)throw err('UNAVAILABLE','MCP child not ready');
    if(!frame||frame.version!==1||frame.method!=='tools/call'||
       typeof frame.deviceId!=='string'||!UUID.test(frame.deviceId)||
       typeof frame.sessionId!=='string'||!UUID.test(frame.sessionId)||
       typeof frame.requestId!=='string'||!UUID.test(frame.requestId)||
       frame.params?.name!=='read_file'){
      throw err('DENIED','Only authenticated, read_file-only tool frames allowed');
    }
    const args=checkedRead(frame.params.arguments,root,maxFileBytes);
    const out=await send('tools/call',{name:'read_file',arguments:args});
    if(out.error)throw err('UPSTREAM','Local MCP rejected read_file');
    if(!out.result || typeof out.result!=='object')throw err('UNAVAILABLE','Invalid MCP result');
    return out.result;
  }
  function close(){shutdown();}
  return Object.freeze({start,handle,close});
}
