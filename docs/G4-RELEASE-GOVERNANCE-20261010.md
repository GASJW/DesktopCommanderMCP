# G4 — Consolidação e publicação governada do VPS Commander

**Data:** 2026-10-10 horário local / 2026-10-11 UTC.
**Estado:** PRs, ancestry e checks GREEN; **MERGE BLOQUEADO** pela ausência comprovada de proteção do `main` e de revisões humanas. Código em produção G3.5 continua funcionando sem mudança/redeploy.

## Estado observado do GitHub (fonte: API live)

- Repositório público: `GASJW/DesktopCommanderMCP`, fork do Desktop Commander, default branch `main`.
- `GET /repos/GASJW/DesktopCommanderMCP/branches/main`: **`protected=false`**, `protection.enabled=false`; SHA do main `7bad545f4524d6b46ca84369b0015f4ebf151fec` quando auditado.
- `GET /repos/GASJW/DesktopCommanderMCP/rulesets?includes_parents=true`: array vazio.
- `GET /repos/.../branches/main/protection` retornou 403 `Resource not accessible by integration`; **não** interpretar 403 isolado como evidência de proteção. A evidência independente `protected=false` + nenhum ruleset suporta o RED.
- PRs #1–#6: abertos, todos Draft, nenhum review submetido, `mergeable=true` no momento da primeira leitura. GitHub não está bloqueando merge por regra de branch; o projeto exige proteção antes de publicar.

## Sequência de integração (NÃO executar antes do gate)

| Ordem | PR | Branch cabeça | Base atual | Entrega |
|---|---|---|---|---|
| 1 | [#1](https://github.com/GASJW/DesktopCommanderMCP/pull/1) | `feat/vps-commander-foundation` | `main` | G1/G2 gateway + Cloudflare Access/tunnel |
| 2 | [#2](https://github.com/GASJW/DesktopCommanderMCP/pull/2) | `feat/g3-executor-isolation` | `feat/vps-commander-foundation` | G3.1 UIDs/socket |
| 3 | [#3](https://github.com/GASJW/DesktopCommanderMCP/pull/3) | `feat/g3-audit-trail` | `feat/g3-executor-isolation` | G3.2 journald |
| 4 | [#4](https://github.com/GASJW/DesktopCommanderMCP/pull/4) | `feat/g3-recovery` | `feat/g3-audit-trail` | G3.3 recuperação |
| 5 | [#5](https://github.com/GASJW/DesktopCommanderMCP/pull/5) | `feat/g3-operational-limits` | `feat/g3-recovery` | G3.4 limites |
| 6 | [#6](https://github.com/GASJW/DesktopCommanderMCP/pull/6) | `feat/g3-access-hardening` | `feat/g3-operational-limits` | G3.5 autorização OAuth |

Todas as relações `base → head` foram verificadas via compare API com `behind_by=0` antes e após o primeiro ciclo de sincronização. As alterações G1–G3.5 correspondem a 120 commits à frente do main inicialmente, mais merges de sincronização do CI; `main` ainda não recebeu nada.

## Correção do check Codespell (não alterou runtime)

- PR #1 tinha **Codespell RED**, enquanto testes do gateway estavam GREEN. O log apontou 29 falsos positivos no material operacional em português (como `comandos`, `cliente`, `administrativo`).
- Atualizada `.codespellrc` e principalmente `.github/workflows/codespell.yml` com `skip: ./docs` na ação Codespell (o container da action não estava adotando automaticamente a config), preservando a análise dos módulos, scripts, README e workflows.
- Gatilho Codespell antes só aceitava `pull_request` para a base `main`; alterado para todos os PRs, incluindo bases de feature branch. O check continua no `push` de `main`.
- A configuração foi propagada por commits de integração em #2–#6, cada qual com dois pais Git (branch anterior + branch da base atualizada). `update_ref` foi feito sem force, preservando ancestralidade e históricos.
- Após propagação, **ambos os checks GREEN no HEAD dos seis PRs**: `gateway-tests` (workflow `VPS Commander Gateway Tests`) e `Check for spelling errors` (workflow `Codespell`).
- Testes automatizados cobrem G3.1–G3.5, enquanto verificação operacional live anterior certificou o Commander, Cloudflare OAuth e recuperação. Nenhum deploy, reinício ou chamada mutante ao ambiente ocorreu durante G4.

## Gate obrigatório: proteger `main`

**A proteção é uma configuração GitHub administrativa que o conector disponível não consegue alterar ou ler em detalhe.** Deve ser feita pelo proprietário com permissões de administração:

1. Acessar `https://github.com/GASJW/DesktopCommanderMCP/settings/rules` (GitHub Settings → Rules → Rulesets; alternativamente Settings → Branches → Branch protection rule).
2. Criar ruleset de branch com enforcement **Active** e alvo exato **`main`**. Exigir *Pull request before merging*.
3. Exigir *Required status checks*: `gateway-tests` e `Check for spelling errors`; checks com sucesso no HEAD e sem pendências.
4. Bloquear **force push**, exclusão de branch, e bypasses não intencionais. Preferir *Require conversation resolution* quando aplicável.
5. Exigir aprovação humana apenas se houver segundo revisor elegível: no momento existem **0 reviews** e não foi confirmada a presença de colaboradores independentes. Exigir 1 aprovação sem revisor disponível cria deadlock.
6. Verificar pela API que `branches/main.protected=true`, ruleset efetivo ou check requerido e regras aplicáveis. **Não habilitar merge até esta evidência.**

## Sequência após proteção comprovada

- Confirmar checks e reviews de cada PR atualizado, comparações base/head e que a cadeia está consistente.
- Colocar #1 como Ready for Review, executar revisão governada e integrar em `main` por **merge commit**, evitando squash de branch-base sem rebase de todos os dependentes.
- Retarget #2 para `main` depois de #1 integrado; executar checks na nova base e integrar por merge commit; repetir por #3 → #6, sequencialmente. Não fundir PR filho dentro de base branch e chamar isso de publicação em `main`.
- Com `main` equivalente ao código G3.5 testado, confirmar PRs merged e SHA final. Em VPS `gui`, confirmar que a instalação ativa está no commit G3.5 funcional. Não redeployar automaticamente somente para alinhar branch/repo; executar somente após evidência de delta e gates adequados.
- Deletar branches apenas quando confirmado que não são necessárias; manter tags/evidências GitHub e Notion.

## Riscos e limitações

- Repositório é **público**. Documentos de evidência não devem incluir JWTs, e-mails exatos, Cloudflare tunnel tokens, chaves ou logs brutos. Os controles de runtime (e-mail allowed, Cloudflare Access, socket privado) permanecem obrigatórios.
- A interface de código mostra checks verdes, mas **checks sem proteção do `main` não são uma barreira de merge**.
- Revisão humana não foi feita; documentação e testes automatizados não equivalem a inspeção de segurança externa.
- A implementação G3.5 é owner-only, sem RBAC por ferramenta. Não elevar permissão do executor nem publicar o endpoint sem Access.

## Gate de saída G4

`G4_MAIN_PROTECTED=true`, `G4_REQUIRED_CHECKS=GREEN`, `G4_PR_CHAIN_INTEGRATED=YES`, `G4_DEPLOYMENT_UNCHANGED_OR_GOVERNED=YES`.

Até esses quatro gates, **G4 = PARTIAL / BLOCKED ON MAIN PROTECTION**, PRs permanecem Draft. G1–G3.5 continuam GREEN operacionalmente.
