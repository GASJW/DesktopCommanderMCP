'use strict';

// This is a UI candidate only. The owner-authenticated, CSRF-protected API
// has not been mounted on the G6 Gateway. Without explicit {enabled:true}
// and a server-provided CSRF token, all actions remain disabled.
const API='/dashboard/api/g7/pairing';
const status=document.getElementById('api-status');
const list=document.getElementById('request-list');
const count=document.getElementById('request-count');
const template=document.getElementById('request-template');
const FP=/^[a-f0-9]{64}$/;
const CODE=/^[A-F0-9]{10}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function codeOf(value){
  return typeof value==='string'?value.replace(/[\s-]/g,'').toUpperCase():'';
}
function message(value,isError=false){
  status.textContent=value;
  status.classList.toggle('error',isError);
}
async function json(url,options={}){
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),6000);
  try{
    const response=await fetch(url,{
      ...options,signal:controller.signal,cache:'no-store',
      credentials:'same-origin',redirect:'error',
      headers:{accept:'application/json',...(options.headers||{})},
    });
    if(!response.ok)throw new Error('API indisponível');
    const data=await response.json();
    if(!data || typeof data!=='object' || Array.isArray(data))throw new Error('Resposta inválida');
    return data;
  }finally{clearTimeout(timeout);}
}
async function mutate(action,item,code,csrf){
  if(!['approve','reject'].includes(action)||!UUID.test(item.requestId)||
    !FP.test(item.fingerprint)||typeof csrf!=='string'||csrf.length<24){
    throw new Error('Solicitação inválida');
  }
  if(action==='approve'&&!CODE.test(codeOf(code)))throw new Error('Código deve ter 10 caracteres');
  return json(API+'/'+action,{
    method:'POST',
    headers:{'content-type':'application/json','x-vpsc-csrf':csrf},
    body:JSON.stringify({
      requestId:item.requestId,
      expectedFingerprint:item.fingerprint,
      ...(action==='approve'?{code:codeOf(code)}:{}),
    }),
  });
}
function renderItem(item,csrf,refresh){
  if(!item||typeof item.name!=='string'||item.name.length>64||
    typeof item.platform!=='string'||!FP.test(item.fingerprint)||
    !UUID.test(item.requestId))return null;
  const node=template.content.firstElementChild.cloneNode(true);
  node.querySelector('.device-name').textContent=item.name;
  node.querySelector('.platform').textContent=item.platform;
  node.querySelector('.proof').textContent=item.proofVerified?'Prova verificada':'Aguardando prova';
  node.querySelector('.fingerprint').textContent=item.fingerprint;
  const field=node.querySelector('.typed-code');
  const approve=node.querySelector('.approve');
  const reject=node.querySelector('.reject');
  const busy=(flag)=>{
    field.disabled=flag;
    approve.disabled=flag||!CODE.test(codeOf(field.value))||!item.proofVerified;
    reject.disabled=flag;
  };
  field.addEventListener('input',()=>busy(false));
  approve.addEventListener('click',async()=>{
    if(!item.proofVerified||!CODE.test(codeOf(field.value)))return;
    busy(true);
    try{
      await mutate('approve',item,field.value,csrf);
      field.value='';
      message('Solicitação processada; confirme o dispositivo aprovado e seu estado.');
      await refresh();
    }catch{
      field.value='';
      message('Não foi possível aprovar. Confirme o código no dispositivo e tente novamente.',true);
      busy(false);
    }
  });
  reject.addEventListener('click',async()=>{
    if(!window.confirm('Rejeitar esta solicitação de pareamento?'))return;
    busy(true);
    try{
      await mutate('reject',item,'',csrf);
      message('Solicitação rejeitada.');
      await refresh();
    }catch{
      message('Não foi possível rejeitar. Atualize a página para confirmar o estado.',true);
      busy(false);
    }
  });
  busy(false);
  return node;
}
async function refresh(){
  list.replaceChildren();
  count.textContent='Indisponível';
  let result;
  try{
    result=await json(API+'/pending');
  }catch{
    message('Pareamento ainda não habilitado neste Gateway. Nenhum acesso foi concedido.');
    const p=document.createElement('p');
    p.className='muted';
    p.textContent='A tela está preparada, mas a API autenticada ainda não está publicada.';
    list.append(p);
    return;
  }
  // Intentionally fail closed. A read-only or missing API cannot create
  // enabled controls merely by returning arbitrary pending requests.
  if(result.enabled!==true || typeof result.csrf!=='string' ||
     result.csrf.length<24 || !Array.isArray(result.pending) ||
     result.pending.length>16){
    message('Aprovação indisponível. Nenhuma solicitação pode ser aprovada nesta sessão.');
    const p=document.createElement('p');
    p.textContent='O Gateway não forneceu autorização de aprovação.';
    list.append(p);
    return;
  }
  message('Pareamento disponível. Compare sempre o código e o fingerprint no dispositivo.');
  count.textContent=String(result.pending.length)+' pendente(s)';
  if(!result.pending.length){
    const p=document.createElement('p');
    p.className='muted';p.textContent='Nenhuma solicitação pendente.';
    list.append(p);
    return;
  }
  for(const item of result.pending){
    const element=renderItem(item,result.csrf,refresh);
    if(element)list.append(element);
  }
}
refresh();
