# G3.2 — CERTIFICAÇÃO FINAL LIVE GREEN (2026-10-10, horário local)

**Estado atual: G3.2 GREEN.** Registros reais autenticados comprovados no `journald` em execução SSH root do proprietário, após deployment e smoke via plugin ChatGPT Commander.

Saída observada de `deploy/verify-g3-audit-journal.py`, executado por pipeline `journalctl -u vps-commander.service --since '60 minutes ago' --no-pager -o cat`:

```text
G3_2_JOURNAL_EVENTS=12
G3_2_JOURNAL_VALID=12
G3_2_JOURNAL_VERIFIED_PRINCIPAL=11
G3_2_JOURNAL_DENIED=1
G3_2_TOOL_READ_FILE=PASS
G3_2_TOOL_START_PROCESS=PASS
G3_2_TOOL_WRITE_FILE=PASS
G3_2_SCHEMA_VIOLATIONS=0
G3_2_JOURNAL_CERTIFICATION=GREEN
```

A janela inclui chamadas reais de `start_process`, `read_file` e `write_file` feitas pelo conector ChatGPT. A análise foi restrita a metadados: nenhum conteúdo de comando, token, arquivo ou identidade bruta foi impresso. O operador já havia comprovado `G3_2_AUDIT_SYSTEMD=BOOTSTRAP_GREEN`, 16/16 testes de gateway e evento 401 registrado. Os túneis `vps-commander` e `cofre` estavam healthy, com quatro conexões cada.

**Limites inalterados:** registros journald não são imutáveis, retenção depende da configuração do host, eventos cobrem requisições MCP (não subprocessos), falha do destino de log não bloqueia execução e crash pode perder registros. Esses limites pertencem a fases futuras, não contradizem o G3.2 aprovado.

**Governança:** PR #3 permanece Draft até integração protegida/revisão, apesar de G3.2 operacional GREEN. Próximo marco independente: G3.3 recuperação de falhas do gateway, executor e conector, sem tocar em Cloudflare Access ou privilégios.

---

# G3.2 — POST-DEPLOY STATUS, 2026-10-10 (local) / 2026-10-11 (UTC)

**Current state: deployment GREEN / ChatGPT authenticated MCP smoke GREEN / privileged journald inspection PENDING.** Older sections below contain historical pre-deployment state.

## Owner bootstrap observed
- Owner ran Git fetch + branch switch to `feat/g3-audit-trail`, then `deploy/bootstrap-g3-audit.sh` over direct root SSH.
- Bootstrap output: **16/16 tests PASS**, `G3_2_AUDIT_SYSTEMD=BOOTSTRAP_GREEN`.
- Bootstrap confirmed anonymous local HTTP 401 event was written to the journald; therefore logging activated successfully (this test does not establish authenticated tool events).

## ChatGPT Commander real post-deploy verification (no RDC)
- Authenticated `mcp__Commander__start_process` returned `G3_2_CHATGPT_LIVE_SHELL=GREEN` on host `gui` as `vpscommander` at **2026-10-11T00:08:41Z**.
- `vps-commander.service` active, `vps-commander-executor.service` active and `cloudflared-vps-commander.service` active.
- Gateway systemd User=`vpsc-gateway`, Environment includes `VPS_COMMANDER_AUDIT_ENABLED=1`.
- Authenticated `read_file /etc/os-release` PASS, `write_file` and read-back of `/var/lib/vps-commander/workspace/g3-audit-live-e2e-20261010.txt` PASS; file contained `G3_2_CHATGPT_LIVE_FILE_GREEN`.
- Cloudflare API confirmed both `vps-commander` and unrelated `cofre` tunnels **healthy**, 4 connections each.
- The Commander executor's `journalctl -u vps-commander.service` returned `No journal files were opened due to insufficient permissions`. This is expected from G3.1 least-privilege isolation. Do not grant executor journal access.

## Privileged audit certification remaining
- Created read-only `deploy/verify-g3-audit-journal.py`; checks strict event JSON fields and verifies an authenticated pseudonym and successful `tools/call` for `start_process`, `write_file`, and `read_file` without displaying any event payload, raw line, identity, command, file path or token.
- Local verifier check: `python3 -m py_compile` PASS, 3 synthetic valid events verified GREEN. **Synthetic events do not certify real journald evidence.**
- Ask owner to run direct SSH root:
```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code pull --ff-only
sudo journalctl -u vps-commander.service --since '60 minutes ago' --no-pager -o cat \
  | python3 /opt/vps-commander/code/deploy/verify-g3-audit-journal.py
```
- Expected `G3_2_JOURNAL_CERTIFICATION=GREEN` and `G3_2_SCHEMA_VIOLATIONS=0`. If RED, gather only the sanitized diagnostics; do not share raw JWT/log lines.
- PR #3 stays Draft until real post-deploy audit is certified. Do not claim G3.2 final GREEN prematurely.

---
# G3.2 — Auditoria MCP: implementação e certificação candidata (2026-10-10)

**Estado:** implementação/testes do candidato GREEN; **auditoria em produção ainda não ativada**. O runtime atual G3.1 permanece operacional.

## Fonte da verdade — runtime
- VPS gui: gateway `vps-commander.service` como `vpsc-gateway`, executor `vps-commander-executor.service` como `vpscommander`, via socket Unix `0660`.
- Ambos ativos; Cloudflare Access OAuth e tunnel existentes não sofreram mudanças neste delta.
- Observação read-only: gateway já usa `StandardOutput=journal`, mas atualmente não emite um registro específico por chamada de ferramenta.
- O usuário do executor não possui permissão para ler o `journalctl -u vps-commander.service` diretamente; consulta administrativa exige root ou política explícita, NÃO concedida.

## Política de auditoria (mínima, metadados apenas)
Quando `VPS_COMMANDER_AUDIT_ENABLED=1`:
- Um evento JSON estruturado por requisição HTTP MCP completada/encerrada (também recusas de autenticação), com `event=vps_commander_audit`, `version=1`.
- `request_id`: UUID local gerado pelo gateway, sem confiar no ID JSON-RPC fornecido pelo cliente.
- `started_at`: timestamp ISO UTC do início da requisição; `duration_ms`: duração monotônica em milissegundos.
- `identity`: pseudônimo estável `cf_<SHA-256 prefix>` obtido SOMENTE do issuer + subject do JWT Access verificado, ou `anonymous` / `local-authenticated` nos modos de teste.
- `route` (`mcp`, `healthz`, `other`), `http_method`, `operation` conhecida (`tools/list`, `tools/call` etc.) e `tool` saneada para identificadores curtos.
- `http_status` e `outcome` (`ok`, `denied`, `invalid_request`, `tool_error`, `rpc_error`, `unavailable`, `disconnected`).
- **Nunca registrar** JWT, bearer, headers, e-mail, IP, payload integral, arguments, shell command, filepath, resposta, erro bruto ou body.
- O pseudônimo pode ser associado a identidades no provedor Access conforme política e retenção de logs desse provedor, mas não contém o e-mail no journald.

## Implementação
- `gateway/audit.mjs`: normalização allowlist, pseudônimo verificado, correlação e emissão de JSON por conclusão.
- `gateway/access-auth.mjs`: adiciona `verifyPrincipal` sem mudar o comportamento booleano existente e só retorna subject após assinatura RS256 e claims válidas.
- `gateway/server.mjs`: integra o audit recorder (ativação explícita pelo env da unidade), classifica ferramentas e resultados.
- `deploy/systemd/vps-commander-g3.service`: ativação `VPS_COMMANDER_AUDIT_ENABLED=1`, `StandardOutput=journal`, `SyslogIdentifier=vps-commander`.
- `deploy/bootstrap-g3-audit.sh`: ativação via root SSH com backup, testes, unidade verificada, negativa HTTP 401 e exigência de registro do evento no journald. Não altera DNS nem Cloudflare.
- `deploy/manual-smoke-g3-audit.mjs`: smoke com executor Desktop Commander REAL usando porta HTTP e socket Unix efêmeros, sem reiniciar o serviço ativo.

## Evidência GREEN
- O primeiro teste na VPS encontrou EPIPE porque os testes mock herdavam `VPS_COMMANDER_EXECUTOR_SOCKET` do runtime G3; corrigido para fixture explícita ter precedência sobre o socket de produção.
- Conjunto anterior 14/14 PASS após correção; conjunto completo com testes de systemd e rollback **16/16 PASS** na VPS.
- Smoke real da ferramenta via conexão efêmera: `G3_2_REAL_AUDIT=GREEN`, `MCP_TOOLS=26`, `AUDIT_EVENTS=3`. Executou `start_process` e `read_file`, validou ausência do comando, path e token nas entradas auditadas.
- Último CI: https://github.com/GASJW/DesktopCommanderMCP/actions/runs/38094737151 — GREEN.
- Serviços ativos ao final dos testes; nenhuma mutação ao runtime produtivo nesta sessão.

## Handoff: ativação controlada via SSH root (AINDA NÃO EXECUTADA)
Partindo do checkout G3 limpo:
```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code remote set-branches --add origin feat/g3-audit-trail
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code fetch origin
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code switch --track origin/feat/g3-audit-trail
sudo bash /opt/vps-commander/code/deploy/bootstrap-g3-audit.sh
```
Esperado: `G3_2_AUDIT_SYSTEMD=BOOTSTRAP_GREEN`. O bootstrap reinicia brevemente somente o gateway, guarda a unidade antiga em `/root/vps-commander-g3-audit-backup` (0700), e tenta restaurá-la automaticamente em caso de erro.

Depois do bootstrap:
1. Testar novamente no plugin ChatGPT: chamada real inofensiva `start_process` e `read_file`.
2. Por SSH root verificar entradas `journalctl -u vps-commander.service -n 80 --no-pager -o cat | grep '"event":"vps_commander_audit"'`, SEM imprimir tokens ou bodies (o logger não deve incluí-los).
3. Confirmar registros com ferramenta e identidade pseudonimizada e resultado consistente.
4. Verificar ambos os serviços e túneis `vps-commander` e `cofre` saudáveis. Manter PR Draft até estas provas.

## Limitações e riscos explicitados
- Journald é a fonte operacional: os registros **não são prova criptográfica nem um armazenamento imutável**; retenção e persistência dependem da configuração do host (não alterada neste gate).
- O logger usa stdout padrão; falhas do destino de log não bloqueiam a operação MCP. Para durabilidade/alertas fortes, um gate de armazenamento durável separado seria necessário.
- Trilha registra **requisições MCP**, não o conteúdo de cada comando shell nem processos secundários iniciados pelo usuário; isso é deliberado para minimizar segredos.
- Em caso de interrupção abrupta do processo, a requisição que estava em andamento pode não gerar evento de conclusão.
- G3.3 (recuperação), G3.4 (limites) e G3.5 (segurança OAuth expandida) continuam fora deste PR.

## Governança
- Branch dedicada `feat/g3-audit-trail` derivada da G3.1; PR #3 Draft. Não fazer merge até testes pós-deploy GREEN.
- Não conceder root, sudo ou acesso ao journald para o executor. Cloudflare Access, DNS, túnel `cofre`, Pantheon, Hermes e OpenMausBot permanecem intactos.
