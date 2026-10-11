# G3.5 — Cloudflare Access OAuth e autorização MCP (2026-10-10/11)

**Estado inicial:** implementação candidata e testes GREEN; deploy real ainda NÃO realizado na data deste registro. Produção permanece G3.4.

## Baseline live — leitura sem mutação
- App Access `VPS Commander MCP` (self_hosted), domínio `commander.supercerebro.me`, app launcher oculto, sessão Access de 8h, Managed OAuth habilitado.
- Aplicação com **uma única política** `VPS Commander Owner Only`, decisão `allow`, inclusão por **um único e-mail** (valor não copiado a GitHub/Notion), sem regras globais de bypass ou permissões gerais.
- Tunnel dedicado `vps-commander` aponta hostname exato para `http://127.0.0.1:8787`, com `originRequest.access.required=true`, audiência exigida e teamName definido. Fallback de ingress é HTTP 404.
- Gateway local `vps-commander.service` está active como `vpsc-gateway`, valida assinatura Access RS256 via JWKS, `iss`, `aud`, `sub`, `email` owner-only e `exp/iat/nbf`. Modo Access **não aceita** bearer local.
- Executor roda como `vpscommander` via socket Unix, sem root. Sua autorização é um único proprietário + privilégios Linux limitados, **não papéis diferentes por ferramenta**.
- Frontend externo Cloudflare impõe política owner-only e injeta `Cf-Access-Jwt-Assertion`; origem valida criptograficamente em vez de confiar na presença da header.

## Menor delta de segurança
- `gateway/access-auth.mjs`: rejeita JWT assinado internamente inconsistente (`iat > exp`, `nbf > exp`) ou com duração `exp - iat > 24h` (o app Access tem sessão 8h). Preserva tolerância existente de 30s para diferença de relógio.
- `gateway/server.mjs`: allowlist de métodos RPC cliente expostos `initialize`, `ping`, `tools/list`, `tools/call`; notificações permitidas `notifications/initialized` e `notifications/cancelled`, sem ID. Outros métodos => HTTP 404, JSON-RPC -32601. Não são encaminhados ao executor.
- `tools/call` exige nome simples no formato `[A-Za-z][A-Za-z0-9_-]{0,79}` e argumentos objeto opcional; invalidação => HTTP 400, JSON-RPC -32602.
- ID JSON-RPC precisa ser string ou inteiro seguro; notificações não podem ter ID. Bloqueia requests de ferramenta sem ID (não executa silenciosamente).
- Mantém proteção a Origin de navegador, bind loopback, cgroup, auditoria de metadados, recuperação sem replay e cotas G3.4.

## Evidências GREEN candidatas
- Matriz de assinatura JWKS sintética: owner válido PASS; email diferente, audiência, assinatura, expiração, claim iat/nbf inválida e durações absurdas DENIED.
- Testes de proxy MCP: métodos fora de allowlist DENIED sem executar; nomes/args inválidos DENIED; valid tools/list e tools/call PASS; eventos auditados sem incluir email, token ou argumento.
- Suite completa no próprio host Ubuntu **37/37 PASS**; testes de rollback pré-existentes e script de implantação G3.5 cobertos.
- Smoke com o Desktop Commander REAL, mas **conexão em socket Unix/HTTP temporários** e JWT de teste com RSA: 26 ferramentas, shell `G3_5_REAL_OAUTH_GREEN`, leitura de `/etc/os-release`, negativas de email não autorizado, JWT ausente, método não permitido e nome de ferramenta inválido: `G3_5_REAL_SMOKE=GREEN`.
- Nenhuma requisição de teste malicioso foi enviada ao endpoint Cloudflare público; nenhum serviço produtivo foi reiniciado.

## Segurança e riscos não cobertos
- Access owner-only **não limita individualmente** `start_process` e as demais 26 ferramentas. O executor pode ler/escrever dentro das permissões do usuário Linux. O usuário aceita esse poder de automação; não afirmar RBAC por ferramenta inexistente.
- JWTs válidos podem ser reproduzidos até expirar; Access e OAuth gerenciam sessão. Não existe prevenção de replay por request/nonce no gateway.
- Protocolo permite clientes adicionais/métodos futuros, mas o gateway G3.5 os rejeitará até aprovação explícita; monitorar regressões no uso real do ChatGPT.
- Testes sintéticos de JWKS **não são** substitutos de autenticação real ChatGPT, que deve ser testada após implantação.
- Rate-limiting por IP/WAF, análise completa de pentest, proteção contra admin comprometido e persistência imutável de logs estão fora do escopo deste gate.

## Deploy governado preparado
- `deploy/bootstrap-g3-access.sh` exige SSH root e branch `feat/g3-access-hardening`, Git limpo, quatro serviços saudáveis, usuários separados, modo Access ativo, suíte 37/37 PASS, rollback para `feat/g3-operational-limits`, permissões dos módulos no mínimo 0644 para código não secreto e espera de até 30s pelo túnel dependente.
- Reinicia **somente** gateway, mantém PID do executor e túnel cofre. Valida HTTP 401 local anônimo, gateway e executor ativos e túnel estabilizado.
- Se o lançamento falhar, faz rollback ao G3.4 (com permissões saneadas e health checks).
- Não executar load test nem fuzz de autorização no endpoint público.

### Fluxo de aplicação (ainda não executado)
```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code remote set-branches --add origin feat/g3-access-hardening
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code fetch origin
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code switch --track origin/feat/g3-access-hardening
sudo bash /opt/vps-commander/code/deploy/bootstrap-g3-access.sh
```

Critério para G3.5 GREEN real: `G3_5_GATEWAY_DEPLOY=BOOTSTRAP_GREEN`, plugin ChatGPT autenticado com shell/read_file/write_file funcionando, quatro serviços ativos, ambos túneis Cloudflare healthy e Access owner-only preservado. Somente após estes gates aceitar GREEN operacional. PR Draft até revisão/merge protegidos.
