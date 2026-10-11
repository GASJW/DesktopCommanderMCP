# G3.4 — PRIMEIRO DEPLOY RED, G3.3 RESTAURADO, BOOTSTRAP CORRIGIDO (10/10/2026 local / 11/10 UTC)

**Estado atual: produção G3.3 GREEN; G3.4 candidato GREEN, mas implantação G3.4 NÃO certificada.** Este relatório substitui o status de candidato inicial indicado abaixo. Não repetir o antigo bootstrap sem obter os commits corretivos.

## Incidente observado

O operador executou `deploy/bootstrap-g3-limits.sh`: 29/29 testes PASS, mas o probe da porta `127.0.0.1:8787` não conseguiu conectar durante a janela curta; o bootstrap emitiu `G3.4 gate RED, restoring prior gateway release` e trocou o repositório de volta para `feat/g3-recovery`. Isso **não é** `G3_4_GATEWAY_DEPLOY=BOOTSTRAP_GREEN`.

Um primeiro teste via plugin Commander falhou internamente. Por contingência, utilizou-se Remote Desktop Commander **somente na VPS gui**, sem alterar serviços externos: `vps-commander.service` estava em restart-loop, sem porta 8787; executor e túnel cofre permaneciam ativos, e o túnel dedicado tentava reconectar.

O `journalctl` root revelou `Error: EACCES: permission denied, open '/opt/vps-commander/code/gateway/server.mjs'`. `stat` confirmou `gateway/server.mjs` e `gateway/audit.mjs` em **mode 0600 root:root**, incompatíveis com o UID runtime `vpsc-gateway`. Git os registra como 100644. **O `umask 077` do bootstrap combinado a `git switch` root no rollback pôde criar os módulos como 0600**. Isso explica inequivocamente o *rollback quebrado*, mas não permite atribuir a falha da prontidão inicial do G3.4 apenas a permissões.

Evidência adicional do journal: em 01:16:51 UTC houve uma inicialização G3.4 com `MCP gateway: http://127.0.0.1:8787` e evento de auditoria HTTP 401; em 01:16:52 UTC iniciou-se o restart do rollback e apareceram falhas EACCES. Portanto a inicialização da versão candidata ocorreu **tardiamente**, próxima do rollback. A janela anterior de prontidão era 40 × 0,25 s (~10 s); a relação exata entre atraso de inicialização e probe ainda não foi reproduzida sob root em produção.

## Recuperação executada

Como root via contingência, alterou-se **apenas o modo de dois arquivos não secretos e versionados** para `0644`:
- `/opt/vps-commander/code/gateway/server.mjs`
- `/opt/vps-commander/code/gateway/audit.mjs`

Sem `chown` recursivo, sem credenciais lidas, sem alterações em Cloudflare. O `systemd` se recuperou por `Restart=on-failure`, com `vps-commander.service=active`, executor e túneis ativos, `GET /healthz` anônimo HTTP 401 e real ChatGPT Commander `start_process` + `read_file /etc/os-release` PASS (`G3_3_ROLLBACK_RECOVERED=GREEN`).

## Correção de engenharia G3.4 entregue mas ainda não implantada

`deploy/bootstrap-g3-limits.sh` foi corrigido para:
- validar via Git (`100644`) a natureza dos três módulos do gateway (`server.mjs`, `audit.mjs`, `access-auth.mjs`) e ajustar **somente** esses arquivos não secretos para `0644`, testando `runuser -u vpsc-gateway -- test -r` antes do restart;
- aplicar a mesma verificação após `git switch` de rollback, pois o script roda com `umask 077`;
- criar um backup root-only **único por tentativa** com `mktemp -d` sem sobrescrever a evidência da falha anterior;
- ampliar o probe de prontidão para até ~30 segundos, suprimindo ruído dos `curl` transitórios;
- confirmar explicitamente o HTTP 401 e o estado `active` do gateway **após o rollback**, anunciando `G3_4_ROLLBACK=GREEN_G3_3_RESTORED` ou RED correspondente;
- manter validação de usuários Linux isolados, worker PID inalterado, auditoria, dependência `Wants` sem `Requires`, e túneis preservados.

A suite ampliada de regressão passou **30/30 testes** na VPS em checkout candidato isolado; `bash -n` do bootstrap passou. O daemon de produção permanece G3.3. O último comando composto de teste retornou exit 128 **após os testes** porque o usuário restrito do Commander tentou consultar `.git` do checkout root-owned; isso não é erro da suíte nem do gateway e não se deve alterar a permissão do `.git` para contorná-lo.

**G3.4 permanece RED no gate de implantação real até novo cutover e smoke autenticado**, agendados apenas após revisão. Não efetuar teste volumoso ou fault injection no endpoint público.

---

# G3.4 — Limites operacionais / proteção contra sobrecarga (10/10/2026)

**Estado: candidato GREEN (29/29 testes VPS + smoke Desktop Commander real); NÃO implantado na unidade ativa.**

## Auditoria READ-ONLY da VPS gui
- Ubuntu 24.04.4 LTS, hora da observação 2026-10-11T01:09:58Z.
- RAM: 7941 MiB total, 4761 MiB disponível; swap 3914 MiB total, 3329 MiB utilizada.
- Pressão de memória recente `/proc/pressure/memory`: `some avg10=0.00`, `full avg10=0.00`. `vmstat` última amostra com `si=0`, `so=0`; swap historicamente ocupada **não demonstra** pressão atual por si só.
- Processos zumbis no momento da verificação: 0. Print de 12 zumbis era anterior e não se repetiu.
- Filesystem raiz: 98 GiB, 80 GiB usados, 14 GiB livres, 86% de utilização. Não limpar arquivos alheios nem executar `swapoff` sem investigação.
- Limites systemd **já em produção**:
  - Gateway: usuário não-root `vpsc-gateway`; `MemoryMax=250M`, `TasksMax=64` (memória cgroup observada ~26 MiB e 11 tarefas).
  - Executor: usuário não-root `vpscommander`; `MemoryMax=900M`, `TasksMax=128` (memória ~105 MiB e 32 tarefas).
  - Tunnel dedicado: `MemoryMax=256M`, `TasksMax=96` (~19 MiB, 10 tarefas).
- `CPUQuota` atualmente sem restrição. Não impor quota arbitrária sem evidência e qualificação do workload.

## Problemas encontrados no código G3.3
- Input: existe limite de corpo 1 MiB, mas escrita HTTP de resultado de ferramenta é ilimitada.
- Executor MCP stdout JSONL aceitava até ~16 milhões de caracteres por linha já construída; não cortava um stream sem newline em bytes.
- Peer controla no máximo 16 pendências; antes do G3.4 não devolvia resposta explícita HTTP 429 com `Retry-After` quando gateway já estava saturado.
- A resposta da ferramenta poderia pressionar memória do gateway (`MemoryMax=250M`) ao serializar muitas saídas grandes paralelas.

## Delta implementado na branch `feat/g3-operational-limits`
- `gateway/server.mjs`: default 2 MiB por resposta JSON HTTP de ferramenta (bytes UTF-8), mensagem de erro JSON-RPC sanitizada HTTP 502 e convite a usar leitura por chunks; sem retornar o payload excedente.
- Parser de JSONL upstream limitado a 4 MiB por frame **durante o recebimento**, inclusive mensagens sem newline. Se ultrapassar, fecha apenas o transporte/Peer e marca operações em curso como indisponíveis, sem repetir efeitos colaterais. G3.3 RecoveringPeer refaz handshake em socket novo.
- Limite de requisições MCP simultâneas no gateway: default 16. Quando excedido, HTTP **429** com header `Retry-After: 1`, sem enviar essa chamada ao executor.
- Configurações opcionais: `VPS_COMMANDER_MAX_RESPONSE_BYTES`, `VPS_COMMANDER_MAX_RPC_LINE_BYTES`, `VPS_COMMANDER_MAX_INFLIGHT`, todas com validação fail-closed na inicialização. Defaults 2MiB, 4MiB, 16; máximo permitido 8MiB de resposta, 16MiB de frame e 16 em voo. Configurações inválidas recusadas antes de abrir porta.
- Audit G3.2 agora classifica `busy` e `limit_exceeded` em eventos estruturados, sem guardar comandos, caminhos ou conteúdo do resultado.
- As regras OAuth Access, identidade Linux, socket 0660, recuperação G3.3, unidade `systemd` e túneis Cloudflare permanecem inalterados.

## Evidência GREEN em candidato, sem deploy
- Testes G3.4 para Unicode (bytes reais UTF-8), conteúdo excedente não refletido, retorno de respostas normais, contenção de três chamadas com limite 2 e HTTP 429/Retry-After, frame excessivo com reconnect, caps inválidos e ausência de dados sensíveis no audit.
- Suíte completa: 27/27 PASS inicialmente; após adicionar guardas de rollback/systemd, **29/29 PASS** na VPS real.
- Smoke real usando `Desktop Commander` dist/index.js: **26 ferramentas**; `G3_2_REAL_AUDIT=GREEN` com 3 eventos; `G3_3_REAL_RECOVERY=GREEN` com shell após a reconexão, via processos/porta/socket temporários.
- Produção permaneceu ativa; **não houve teste de carga na porta pública** nem tentativa de derrubar processos reais.

## Implantação preparada (não executada)
- Bootstrap `deploy/bootstrap-g3-limits.sh` exige SSH root direto, branch G3.4, Git limpo, 4 serviços ativos, isolamento de UIDs, dependency `Wants` sem `Requires`, auditoria ativa e suite de testes PASS.
- Mantém executor, túnel `vps-commander`, túnel `cofre` e serviços não relacionados intocados. Reinicia apenas gateway (breve indisponibilidade), exige HTTP 401 para acesso local anônimo e mantém PID do executor. Em erro troca para `feat/g3-recovery` e tenta recuperar gateway.
- Após implantar, certificar chamadas autenticadas reais no ChatGPT Commander (`tools/list`, `start_process`, `read_file`, `write_file`) e status dos túneis. **Não realizar geração volumosa de dados contra o endpoint produtivo**; a prova de limite já foi feita em porta/socket temporários.

```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code remote set-branches --add origin feat/g3-operational-limits
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code fetch origin
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code switch --track origin/feat/g3-operational-limits
sudo bash /opt/vps-commander/code/deploy/bootstrap-g3-limits.sh
```

Esperado: `G3_4_GATEWAY_DEPLOY=BOOTSTRAP_GREEN`. **PR permanece Draft até smoke real pós-implantação e review.**

## Fora do aceite desta etapa
- Limite de armazenamento por quota de filesystem, CPUQuota e políticas de retenção journald: requerem dimensionamento específico, não justificável por observação isolada.
- O timeout MCP de 120s já existente encerra a espera HTTP; **não garante cancelar um processo com efeito colateral no executor**. Não repetir operações mutantes automaticamente.
- Testes de força bruta, limitação por IP, WAF e proteção DoS externos não foram alterados; Cloudflare Access owner-only permanece requisito.
- Os valores do `systemd` são guardrails por cgroup, não uma garantia de isolamento de disco nem de segurança absoluta.

## Governança
- Branch `feat/g3-operational-limits` derivada de `feat/g3-recovery` (PR #4 G3.3, GREEN operacional). PR G3.4 Draft próprio, stacked, sem merge automático.
- Evidência-first, corrigir somente a falha vista; rollback seguro para G3.3.
