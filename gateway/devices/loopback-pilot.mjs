import { createServer } from 'node:http';
import { createAgentChannelTransport } from './agent-channel-transport.mjs';

// Test-only HTTP adapter. Production staging composes the authenticated
// handler directly into its loopback TLS listener and never starts this port.
export async function startLoopbackAgentPilot({
  registry,router,shouldCancelOperation,enableLoopbackPilot=false,host='127.0.0.1',port=0,
}={}){
  if(!enableLoopbackPilot||host!=='127.0.0.1'||port!==0){
    throw new Error('Agent pilot must be explicitly enabled, ephemeral and loopback-only');
  }
  const transport=createAgentChannelTransport({registry,router,shouldCancelOperation});
  const server=createServer(transport.handle);
  server.requestTimeout=10_000;
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  return Object.freeze({url:'http://127.0.0.1:'+server.address().port,
    operationState:transport.operationState,invalidateDevice:transport.invalidateDevice,
    close:async()=>{
      server.closeAllConnections();
      if(server.listening)await new Promise(resolve=>server.close(resolve));
      await transport.close();
    }});
}
