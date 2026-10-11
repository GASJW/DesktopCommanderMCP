import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
  let q;
  try{q=JSON.parse(line)}catch{continue}
  if(!Object.hasOwn(q,'id'))continue;
  let result;
  if(q.method==='initialize') result={protocolVersion:'2025-03-26',capabilities:{tools:{}}};
  else if(q.method==='tools/call'&&q.params?.name==='read_file'){
    result={content:[{type:'text',text:readFileSync(q.params.arguments.path,'utf8')}]};
  } else result={isError:true,content:[{type:'text',text:'unsupported'}]};
  process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:q.id,result})+'\n');
}
