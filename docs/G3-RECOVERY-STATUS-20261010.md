# G3.3 — HOTFIX SYSTEMD APLICADO E VERIFICADO (2026-10-10 local / 2026-10-11 UTC)

**Estado atual:** correção da dependência gateway→executor **GREEN** em produção; G3.3 recuperação após falha real ainda **PENDENTE** de repetição do drill com a nova dependência.

O proprietário aplicou por SSH `deploy/repair-g3-gateway-dependency.sh`, que reportou:
```text
G3_3_DEPENDENCY_REPAIR=GREEN
G3_3_GATEWAY_PID_UNCHANGED=PASS
G3_3_EXECUTOR_PID_UNCHANGED=PASS
G3_3_ORIGIN_ANONYMOUS_HTTP=401
```

Certificação independente via plugin **ChatGPT Commander**, read-only, após o hotfix:
- `systemctl show -P Requires vps-commander.service`: **não inclui** `vps-commander-executor.service`.
- `systemctl show -P Wants vps-commander.service`: **inclui** `vps-commander-executor.service`.
- `systemctl show -P After vps-commander.service`: **inclui** `vps-commander-executor.service`.
- Gateway e executor **active**, PIDs preservados `1617612` e `1617600` respectivamente; `cloudflared-vps-commander.service` e `cloudflared.service` **active**.
- `/healthz` anônimo HTTP 401, shell remoto `G3_3_AFTER_DEPENDENCY_REPAIR_GREEN`.
- API Cloudflare confirmou **ambos** os túneis `vps-commander` e `cofre` **healthy, 4 conexões cada**.
- Nenhuma reinicialização foi necessária ou observada para instalar essa mudança. Autenticação, isolamento e auditoria preservados.

**Próximo gate (ainda não executado desde o reparo):** operador SSH root, sem operações mutantes/em andamento, executar `sudo bash /opt/vps-commander/code/deploy/verify-g3-systemd-recovery.sh --accept-controlled-executor-restart`. O script aprovado agora falha imediatamente caso o PID do gateway seja alterado e não reinicia serviços saudáveis durante rollback. Só aceitar `G3_3_REAL_SYSTEMD_DRILL=GREEN` após observação real de eventos de recovery e execução posterior pelo ChatGPT. Se houver RED, diagnosticar por journal administrativo antes de novo retry.

---

# G3.3 — PRIMEIRO ENSAIO SYSTEMD RED, CORREÇÃO MÍNIMA PREPARADA (2026-10-10 local / 2026-10-11 UTC)

**Estado atual: operação restaurada/saudável; recuperação sem reiniciar gateway NÃO certificada.**

O operador iniciou por SSH o ensaio `verify-g3-systemd-recovery.sh`: último registro visível `G3_3_DRILL_START=CONTROLLED_SINGLE_EXECUTOR_MAIN_SIGKILL`. Não houve evidência final `G3_3_REAL_SYSTEMD_DRILL=GREEN` nesse print.

Inspeção read-only posterior pelo plugin Commander:
- `vps-commander.service=active`, `vps-commander-executor.service=active`, ambos túneis `active`, shell `G3_3_POST_FAILURE_CHATGPT_GREEN`; HTTP `/healthz` anônimo local 401.
- Gateway PID antes do ensaio = `1608565`; após = `1617612`. Executor antes = `1495805`; após = `1617600`. Gateway e executor com `ExecMainStartTimestamp=2026-10-11 00:41:59 UTC`, na janela do ensaio. Portanto o gateway **foi reiniciado**, contrariando o requisito de PID constante.
- O script original executa `recover()` em falha, com `systemctl restart` de ambos os serviços; o reinício observado pode resultar dessa recuperação. Causa exata da falha exige journal privilegiado, que o usuário `vpscommander` não pode ler.
- Uma causa arquitetural provável foi confirmada na configuração ativa: `Requires=vps-commander-executor.service` junto com `After=` liga o ciclo de vida do gateway à unidade do worker, interferindo no teste de queda isolada.

Correção versionada na mesma branch/PR #4 (não aplicada em produção):
- `deploy/systemd/vps-commander-g3.service`: trocar **somente** `Requires=vps-commander-executor.service` por `Wants=vps-commander-executor.service`, preservar `After=`. O gateway inicia com ordenação; perda transitória do worker deve apenas manter a aplicação viva e deixar `RecoveringPeer` reconectar. O boot continua fail-closed quando upstream não está disponível.
- `deploy/repair-g3-gateway-dependency.sh`: aplica hotfix de uma linha via SSH root, com guarda `sed | cmp`, backup root-only, `systemd-analyze verify`, `daemon-reload`, verifica PID gateway/worker **sem reiniciar serviços**, com rollback no erro.
- `deploy/verify-g3-systemd-recovery.sh`: agora falha cedo ao observar mudança de PID do gateway e no rollback reinicia um serviço somente se estiver inativo, evitando mascarar a causa com reinícios desnecessários.
- Testes unitários para `Wants` e contra `Requires` acrescidos; candidato já passou 23/23 na VPS antes do último ajuste do script.

**NÃO repetir o ensaio de falha ainda.** Primeiro aplicar hotfix governado por SSH em momento ocioso:
```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code pull --ff-only
sudo bash /opt/vps-commander/code/deploy/repair-g3-gateway-dependency.sh
```
Resultado esperado: `G3_3_DEPENDENCY_REPAIR=GREEN`, `G3_3_GATEWAY_PID_UNCHANGED=PASS`, `G3_3_EXECUTOR_PID_UNCHANGED=PASS`.

Somente com esta configuração confirmada e sem comandos mutantes ativos repetir o ensaio root `verify-g3-systemd-recovery.sh --accept-controlled-executor-restart`, observar `G3_3_REAL_SYSTEMD_DRILL=GREEN` e certificação autentificada posterior. **G3.3 permanece RED no gate de recuperação real até lá.**

---

# G3.3 — DEPLOY REAL GREEN, ENSAIO DE FALHA SYSTEMD PENDENTE (2026-10-10)

**O operador executou por SSH root a implantação do gateway G3.3.** Print da sessão reporta `G3_3_GATEWAY_DEPLOY=BOOTSTRAP_GREEN` e 19/19 testes PASS. O gateway foi reiniciado nessa implantação e retomou serviço; não há evidência ainda de falha induzida do executor do systemd real.

## Verificação pós-deploy autenticada (ChatGPT Commander)
- `mcp__Commander__start_process`: `G3_3_CHATGPT_REAL_SHELL=GREEN`, `HOST=gui`, `USER=vpscommander`, branch `feat/g3-recovery`.
- `vps-commander.service` active e usuário `vpsc-gateway`; `vps-commander-executor.service` active e usuário `vpscommander`.
- `cloudflared-vps-commander.service` active; `VPS_COMMANDER_AUDIT_ENABLED=1` presente na configuração do gateway.
- `read_file /etc/os-release` PASS (Ubuntu 24.04.4 LTS).
- `write_file` + `read_file` de `/var/lib/vps-commander/workspace/g3-recovery-postdeploy-20261010.txt` PASS: `G3_3_CHATGPT_WRITE=GREEN`.
- Cloudflare API: `vps-commander` healthy, quatro conexões; `cofre` healthy, quatro conexões.
- Teste de falha real **não executado** nessa certificação, por não disparar root/falhas via o Commander de baixo privilégio.

## Ensaio real controlado preparado, NÃO executado
- `deploy/verify-g3-systemd-recovery.sh`: execução apenas por SSH root e argumento explícito `--accept-controlled-executor-restart`; atua apenas sobre o processo principal de `vps-commander-executor.service` via `systemctl kill --kill-whom=main --signal=SIGKILL`. Não usar `systemctl stop`, que pode parar gateway dependente.
- Pré-condições: ambos serviços, ambos túneis ativos; usuários separados; auditoria habilitada; gateway PID existente. Executar somente sem comandos mutantes/longos ativos.
- Validações: executor recebe PID novo e retorna active; gateway fica active com MESMO PID; journald contém, em ordem, eventos `disconnected`, `retry_scheduled`, `reconnected` com esquema restrito; ambos túneis continuam active.
- Falha em qualquer gate provoca tentativa de recuperação dos serviços via `systemctl restart`. Não realiza rollback do código porque o corte do gateway já está GREEN; inspecionar uma falha antes de novas ações.
- `deploy/verify-g3-recovery-events.py`: verificador de metadados que não imprime linhas de journal ou tokens.
- Inspeção do candidato na VPS: **21/21 testes automatizados PASS**, scripts Bash/Python sintaticamente válidos e eventos sintéticos testados `G3_3_SYSTEMD_RECOVERY_EVENTS=GREEN`; **esses eventos são sintéticos e não substituem ensaio real**.

### Execução governada pelo owner SSH
```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code pull --ff-only
sudo bash /opt/vps-commander/code/deploy/verify-g3-systemd-recovery.sh --accept-controlled-executor-restart
```
Esperado: `G3_3_REAL_SYSTEMD_DRILL=GREEN`. Depois executar chamada autêntica de ferramenta via ChatGPT Commander e reinspecionar o estado Cloudflare. **G3.3 não é GREEN final até esse ensaio real passar**; a implantação/smoke do gateway já é GREEN.

---

# G3.3 — Resiliência/recuperação do VPS Commander (2026-10-10)

**Status: candidato GREEN / deployment real ainda não feito.** G3.2 produção e dois túneis continuam saudáveis; não houve fault injection em serviço produtivo.

## Diagnóstico read-only em produção
- Gateway `vps-commander.service`: active, User=vpsc-gateway, Restart=on-failure, RestartSec=5s, Requires=vps-commander-executor.service.
- Executor `vps-commander-executor.service`: active, User=vpscommander, Restart=on-failure, RestartSec=3s, com socket em `/run/vps-commander-ipc/mcp.sock`.
- Cloudflared dedicado `cloudflared-vps-commander.service`: active, Restart=on-failure, RestartSec=8s, independente de `cloudflared.service` (túnel cofre).
- Todos com NRestarts=0 no momento da leitura; nenhuma falha produtiva foi provocada.
- Gap no código anterior: `Peer.fail()` torna o gateway permanentemente `dead` quando o socket fecha. O processo HTTP segue `active`, mas `/healthz` responde 503 até o gateway ser reiniciado manualmente ou por systemd. Nenhum reconnect existia.

## Menor correção entregue
- `gateway/server.mjs`: wrapper `RecoveringPeer` apenas quando `VPS_COMMANDER_EXECUTOR_SOCKET` está definido.
- `onDisconnect` marca executor indisponível, rejeita pending sem reexecutar chamadas, e inicia reconexão com backoff exponencial limitado (250ms até 8s por default).
- Durante a queda, chamadas autenticadas recebem HTTP 503; não são enfileiradas nem repetidas automaticamente (evita dupla execução de operações mutantes).
- Após reconectar, novo handshake `initialize` e `notifications/initialized`; chamadas novas voltam a funcionar no mesmo gateway HTTP.
- Handshake de conexão limitado a 8 segundos, distinto de timeout normal de 120 segundos por ferramenta.
- Telemetria no journald com `event=vps_commander_recovery`: estados `disconnected`, `retry_scheduled`, `reconnected` e números de tentativas/delay. Sem argumentos, credenciais, mensagens de erro bruto ou caminhos.
- Sessões explicitamente encerradas não geram loops de reconexão. Legacy mode sem socket permanece igual.

## Evidências do candidato na VPS gui
- Teste automatizado `gateway/test/recovery.test.mjs`: dois ciclos consecutivos de queda e retorno de executor mock. HTTP 503 no meio, HTTP 200 após reconexão, HTTP 401 anônimo preservado, audit log e telemetry redacted PASS.
- Suíte completa **19/19 PASS** no próprio host Ubuntu, sem substituir gateway da produção.
- Ensaio com Desktop Commander REAL, socket e gateway HTTP efêmeros: `G3_3_INITIAL_TOOLS=26`, `G3_3_DISCONNECTED_HTTP=503`, `G3_3_REAL_RECOVERY=GREEN`, e terminal real após reconnect respondeu `G3_3_REAL_RECOVERY_GREEN`.
- Runtime produtivo continuou `active` durante os ensaios. Nenhum restart em produção executado.

## Bootstrap seguro preparado (ainda não executado)
Versão `deploy/bootstrap-g3-recovery.sh`: exige SSH root, branch `feat/g3-recovery` limpa, serviço gateway/executor/tunnel ativo, dois usuários distintos, testes locais PASS e backup protegido do SHA da branch anterior. Reinicia **somente o gateway**, verifica 401 local (sem autenticação), usuário do gateway, estado do executor e túnel. Se falhar, retorna à branch G3.2 e reinicia gateway; não altera Cloudflare/DNS.

### Handoff do operador
Não executar enquanto existir uma chamada longa do Commander em andamento; o gateway sofrerá uma interrupção curta.
```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code remote set-branches --add origin feat/g3-recovery
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code fetch origin
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code switch --track origin/feat/g3-recovery
sudo bash /opt/vps-commander/code/deploy/bootstrap-g3-recovery.sh
```
Esperado: `G3_3_GATEWAY_DEPLOY=BOOTSTRAP_GREEN`.

### Pós-deploy
- Validar via ChatGPT Commander autenticado: `start_process` inofensivo, `read_file`, escrita e leitura simples; mesma URL OAuth Cloudflare.
- Verificar ambos túneis healthy, audit log ainda em vigor, usuários separados, HTTP anônimo 401.
- Para considerar o G3.3 completo, executar em janela governada teste de queda controlada do processo do executor ou equivalente, comprovando recuperação real e estado do gateway; não testar com `systemctl stop` porque a dependência `Requires=` pode derrubar o gateway e invalidar o objetivo do teste.
- Também revisar resiliência do conector dedicado e recuperação após reboot/serviços sem provocar indisponibilidade nos sistemas preexistentes.

## Gates e limites
- G3.3 candidata GREEN apenas para teste simulado e Desktop Commander real temporário. Não há evidência de failover real no systemd da VPS após falha induzida.
- Nenhum processo em andamento é repetido automaticamente na reconexão. Chamadas que falharam devem ser inspecionadas antes de qualquer retry manual para evitar efeitos duplicados.
- PR independente Draft; base `feat/g3-audit-trail` de G3.2. Não fazer merge ou declarar G3.3 final GREEN até teste pós-deploy.
