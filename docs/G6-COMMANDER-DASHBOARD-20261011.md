# G6 — Commander Control Plane · Dashboard de uso e infraestrutura (candidato)

**Status (2026-10-11):** implementação isolada, ainda NÃO implantada no gateway público. Não afirmar que `/dashboard` está disponível até bootstrap + smoke autenticado real. PR na branch `feat/commander-dashboard`.

## Objetivo e URL

Dashboard em **https://commander.supercerebro.me/dashboard** sob o **mesmo** Cloudflare Access Managed OAuth e regra owner-only já aplicados ao hostname `commander.supercerebro.me`. O endpoint existente `/mcp` não muda de nome nem protocolo. Também não é necessário criar novo DNS/túnel/política Access. Cloudflare Access app read-only observada: `VPS Commander MCP`, host completo, sessão 8h; tunnel ingress dedicado leva ao `127.0.0.1:8787`, origem exige Access e fallback é 404.

## Componentes implementados

- `gateway/dashboard/index.html`, `style.css`, `app.js`: interface responsiva dark, totalmente self-hosted, sem bibliotecas ou CDNs externos; métricas de requisições MCP, taxa de sucesso, p95, ranking de ferramentas, volume e erros dos últimos 60 min, status local de 4 serviços systemd, RAM, disco, load 1m e concorrência.
- `gateway/dashboard/metrics.mjs`: agregados a partir **apenas dos eventos sanitizados** G3.2 `vps_commander_audit`; nunca armazena comandos, argumentos, arquivos, corpo de requisições, JWT, e-mail nem saída da ferramenta. Mantém os últimos 60 minutos em gráfico, amostras de até 512 latências e até 15 min de identidade pseudonimizada; cardinalidade limitada. Sem dependência de leitura do journal ou root; não substitui o journald durável.
- `gateway/dashboard/http.mjs`: assets read-only fixos e endpoint `GET /dashboard/metrics`, inclui sistema local via `systemctl is-active` unprivilegiado, `os` e `statfsSync`; 5s de cache dos estados. Sem comandos ou ferramentas remotos no browser. Respostas `no-store`, CSP bloqueando conteúdo externo/inline, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`. Somente GET/HEAD.
- `gateway/server.mjs`: rotear dashboard somente **depois** da verificação criptográfica da identidade owner-only via Access JWT; em modo local bearer, dashboard responde 404. `/mcp` e `/healthz` preservados.
- `gateway/audit.mjs`: hook opcional de agregação `onEntry` derivado do mesmo evento já sanitizado; sink journald permanece idêntico. Requisições à dashboard não contam como uso do MCP.
- `gateway/test/dashboard.test.mjs` e `deploy/test/dashboard-release.test.mjs`: autenticação/negações, proteção dos endpoints, privacidade, contadores, MCP regressão e deploy governado.

## O que **dispositivos ativos** significa aqui

O MCP atual é instalado em apenas **um host real**, a VPS `gui`. Mostra ela e quatro serviços systemd. Mostra também a quantidade de **identidades criptograficamente autenticadas vistas nos últimos 15 min** pelo gateway, sob IDs pseudonimizados (sem e-mail). **Isso não prova PC remoto online nem sessão aberta:** o Commander proprietário não descobre equipamentos externos via esse gateway. O Gui-PC e outros computadores exigiriam um agente e inventário próprios no futuro. O status `cloudflared.service=active` também não prova sozinho que o túnel está healthy na API Cloudflare; o texto do UI o distingue.

## Limites atuais e observabilidade

- Contadores do painel começam ao **iniciar o gateway com o dashboard** e zeram a cada reinício. Não se confundem com o contador de 183 chamadas do `get_usage_stats` do Desktop Commander, cuja origem/cobertura não é o journal do gateway.
- A série retém 60 min em memória, com até 120 min de buckets guardados; dados duráveis continuam no audit journald G3.2, disponível apenas a operadores privilegiados. O dashboard NÃO lê log bruto.
- Listas de clientes não exibem e-mail, IP, user agent, token, localização nem hostname de navegador, e não podem identificar máquinas físicas.
- Systemd `unknown` será mostrado como **não verificado**, não como serviço ativo. Identidade Auth passa pelas mesmas checagens JWT vigentes.
- Iniciar, parar, reiniciar serviços, ver stdout/stderr, executar shell e modificar permissões NÃO é permitido pela interface.

## Testes e deploy

Testes preliminares do dashboard passaram em porta local efêmera com JWT RS256 sintético e mock executor. Suíte base passa; registrar resultado final do CI no PR. **Não enviar testes negativos para hostname público.**

`deploy/bootstrap-commander-dashboard.sh` (root SSH somente) exige branch `main` protegida, HEAD exatamente main remoto e dois checks GREEN, checkout limpo, gateway/worker/túneis ativos, Access habilitado, UIDs isolados, nenhuma mudança runtime inesperada exceto gateway/audit/dashboard e módulos Git mode 100644 legíveis ao gateway. Testa em isolamento, reinicia somente gateway, espera endpoint dashboard responder 401 anônimo e túnel estabilizar, preserva executor e cofre. Em falha de restart, retorna ao branch funcional G3.5 com modos corretos, restaura gateway e verifica túnel. Não executá-lo da pasta de trabalho `vpscommander` nem antes de PR protegido.

Plano de ativação (após merge e autorização de janela breve de restart): root SSH no `gui`, `git fetch origin`, `switch main`, `pull --ff-only`, executar bootstrap root **pelo caminho versionado**. Não usar RDC para ações ordinárias. O MCP proprietário como usuário restrito realiza todos os pré-checks e smoke posteriores. Bootstrap GREEN é provisório até abrir em navegador com owner Access e executar uma chamada MCP real pós-restart.

## Gate de aceite

1. CI Gateway Tests e Codespell GREEN no PR protegido, merge normal;
2. bootstrap real `DASH_DEPLOY=BOOTSTRAP_GREEN`, `DASH_ROUTE_ANONYMOUS=401`, `DASH_WORKER_PID_UNCHANGED=PASS`;
3. Cloudflare tunnel Commander e cofre healthy pela API, serviços ativos, auditoria ligada;
4. abrir `https://commander.supercerebro.me/dashboard` autenticado e verificar layout/JSON; confirmar que sem login é negado;
5. ChatGPT Commander `start_process`, `read_file`, `write_file` continuam funcionando, sem replay ou mudança de privilégio;
6. registrar evidência Notion/GitHub e somente então declarar G6 GREEN.

**Não alterar:** Pantheon, Hermes, OpenMausBot, `cofre`, DNS/Cloudflare policies existentes, execução do G5.2 pendente ou credenciais Access.
