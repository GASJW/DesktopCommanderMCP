# G2 — Cloudflare Managed OAuth + origem JWT (10/10/2026)

## Estado: G2 PARTIAL / BLOQUEADO NO BOOTSTRAP DO CONECTOR

Este documento registra estado OBSERVADO. Não usar "GREEN" como sinônimo de acesso ChatGPT remoto funcionando.

### Conta Cloudflare — configurado e confirmado via API
- Conta e zona existentes no plano Free, domínio `supercerebro.me` ativo.
- Aplicação Access `VPS Commander MCP`, `self_hosted`, domínio `commander.supercerebro.me`, criada isoladamente.
- ID Access application: `b3b49a3c-89ca-4464-a3c1-a4030e561973`.
- App audience (não secreto): `dad98a6ca40005ed05dfb6cd5721a0f3588c239c06805c07d55cff396d8ccd38`.
- Managed OAuth: `enabled=true`; sessão da aplicação: 8h; não visível no app launcher.
- Política `VPS Commander Owner Only`: decisão `allow`, seleção por email proprietário específico; sem política `everyone`.
- Organização: `https://plain-block-9a74.cloudflareaccess.com`.
- Tunnel: `vps-commander`, `9a11c3d5-cc76-4427-a6d6-b85722f0e4db`, separado do túnel existente `cofre`.
- Ingress remote-managed configurado: `commander.supercerebro.me` -> `http://127.0.0.1:8787`; `originRequest.access.required=true`, `teamName=plain-block-9a74`, `audTag` específico da aplicação; fallback HTTP 404.
- **Ainda NÃO há DNS publicado nem tunnel connector ativo**, portanto não existe endpoint público do VPS Commander.

### Aplicação na VPS — confirmado
- Serviço `vps-commander.service` permanece active/running em `127.0.0.1:8787`, usuário `vpscommander` sem root, sem alterar Pantheon/Hermes/OpenMausBot.
- Código local atualizado no commit `3c8ff87` e testes `node --test gateway/test/*.test.mjs` GREEN: **5/5** (3 JWT/Access + 2 transporte mock).
- O gateway passou ao `VPS_COMMANDER_AUTH_MODE=access` via drop-in `20-access.conf`.
- Origin JWT: verifica assinatura RSA-SHA256 com chaves públicas JWKS de `/cdn-cgi/access/certs`, emissor, audiência, prazo de validade/iat/nbf, email permitido e identidade. Falhas encerram com 401.
- JWKS real confirmado acessível pela VPS (HTTP 200, 2 chaves RSA), mas JWT de usuário real não foi obtido nesta sessão.
- Testes HTTP contra a instância persistente: anônimo = 401, bearer local antigo = 401, JWT falso = 401, serviço active e bind exclusivo a loopback.
- Chamada positiva com credencial real Cloudflare Access (OAuth do ChatGPT) **NÃO CERTIFICADA**.

### Bootstrap do Tunnel — bloqueio concreto
- Token obtido da API Cloudflare e depositado na VPS em `/etc/cloudflared/vps-commander-private/token`, sem expor seu valor no Git ou no Notion, inicialmente `root:root 0600`.
- A tentativa de criar o usuário isolado e cadastrar `cloudflared-vps-commander.service` pelo Remote Desktop Commander foi **bloqueada pelo controle de comandos do RDC** antes da execução. Não houve retry por bypass.
- Unidade systemd preparada: `deploy/systemd/cloudflared-vps-commander.service`.
- Template de drop-in Access: `deploy/systemd/vps-commander-access.conf.example`.
- Próxima ação: executar bootstrap do tunnel diretamente por SSH com acesso administrador, sem RDC, ou por canal explicitamente autorizado. Não registrar DNS antes de um conector saudável e testes de negação.
- **Não transmitir a credencial de túnel em chat**, em issue/PR ou em URL. A credencial já reside na VPS.

### Critérios de fechamento de G2
1. Cloudflared dedicado `active/healthy` sem interferir no `cofre`.
2. DNS `commander.supercerebro.me` apontando ao novo tunnel.
3. Acesso HTTP anônimo externo negado; Origin sem JWT 401.
4. Login OAuth real como proprietário e invocação de `tools/list` validada com JWT assinado + escopo correto.
5. Identidade não autorizada negada; JWT expirado/forjado negado.
6. Em seguida iniciar G3: conectar plugin MCP do ChatGPT e smoke test de comandos e arquivo.

### Rollback
- `systemctl stop cloudflared-vps-commander.service` (se existir).
- `systemctl stop vps-commander.service` para desligar executor.
- Remover apenas DNS/Access/Tunnel do VPS Commander em caso de rollback de publicação; não modificar `cofre` ou serviços pré-existentes.
- Os artefatos Git permanecem na branch de trabalho; PR #1 deve continuar Draft até certificação G2 completa.

Fontes: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/ e https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/ .
