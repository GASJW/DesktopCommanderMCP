#!/usr/bin/env node
import { startG7StagingGateway, readStagingConfig } from './runtime.mjs';
import { parseStagingCommandLine } from './runtime-mode.mjs';

let gateway;
let closing=false;
async function shutdown(signal){
  if(closing)return;
  closing=true;
  try{await gateway?.close();process.stdout.write(JSON.stringify({event:'STOPPED',signal})+'\n');}
  catch{process.stderr.write(JSON.stringify({event:'SHUTDOWN_FAILED'})+'\n');process.exitCode=1;}
}
try{
  const invocation=parseStagingCommandLine(process.argv.slice(2));
  const config=readStagingConfig(invocation.configPath);
  gateway=await startG7StagingGateway(config);
  process.stdout.write(JSON.stringify({event:'READY',runtime:'g7-staging',host:'127.0.0.1',
    port:gateway.port,pid:process.pid})+'\n');
  process.once('SIGTERM',()=>void shutdown('SIGTERM'));
  process.once('SIGINT',()=>void shutdown('SIGINT'));
}catch(error){
  process.stderr.write(JSON.stringify({event:'STARTUP_FAILED',code:error?.code==='TEST_FIXTURE_ENVIRONMENT'?'TEST_FIXTURE_ENVIRONMENT':
    /^[A-Z_]{1,48}$/.test(error?.code??'')?error.code:'CONFIG_OR_STORE',
    detail:String(error?.message??'startup failed').replace(/[\r\n]/g,' ').slice(0,200)})+'\n');
  process.exitCode=1;
}
