const FORBIDDEN_PERSISTENT_ENV=/^(?:NODE_TEST_CONTEXT|NODE_OPTIONS|NODE_V8_COVERAGE|VPSC_STAGING_.*(?:TEST|FIXTURE|SCENARIO|HOOK).*|VPSC_STAGING_(?:NODE|MCP_ENTRYPOINT|TRACE))$/i;

export function assertPersistentStagingEnvironment(env=process.env){
  const selectors=Object.keys(env).filter(name=>FORBIDDEN_PERSISTENT_ENV.test(name));
  if(selectors.length){
    throw Object.assign(new Error('Persistent staging refuses test fixture environment'),{
      code:'TEST_FIXTURE_ENVIRONMENT',
    });
  }
}

export function parseStagingCommandLine(args,{env=process.env}={}){
  let persistent=false;
  let remaining=args;
  if(args[0]==='--persistent-staging'){
    persistent=true;
    remaining=args.slice(1);
    assertPersistentStagingEnvironment(env);
  }
  if(remaining.length!==2||remaining[0]!=='--config'||!remaining[1]){
    throw Object.assign(new Error('usage'),{code:'CONFIG'});
  }
  return Object.freeze({persistent,configPath:remaining[1]});
}
