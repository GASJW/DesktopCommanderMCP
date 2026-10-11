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
