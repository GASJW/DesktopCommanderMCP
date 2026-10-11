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
