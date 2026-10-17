# G7 I2 — contrato observado e contrato de reconciliação

## Evidência I2A no HEAD `f3128902bc573979e74b9d6721fbc2a29a9dfee3`

| Identidade/estado | Gerador e momento | Persistência observada |
|---|---|---|
| `eventId` | `owner-pairing-http.mjs`, `randomUUID()` antes do intent | WAL v1 persiste no intent e outcome; não inclui o requestId literal |
| `requestId` | `pairing.mjs`, `randomUUID()` em `startPairing()` | Estado `pending` em memória; WAL guarda apenas `targetId = SHA-256(requestId)[0..24]` |
| Fingerprint | SHA-256 da chave Ed25519 SPKI em `pairing.mjs` | Pending em memória; após aprovação, trust snapshot salva fingerprint e chave pública |
| `deviceId` | `registry.mjs`, `randomUUID()` dentro de `trustDevice()` | Trust snapshot persiste; não aparece no WAL |
| Trust revision | `durable-trust.mjs`, incrementada por trust/revoke | Snapshot `trusted-devices-v1.json`; ausência significa revisão 0 |
| Outcome de auditoria | HTTP traduz resultado em `accepted`/`denied` | WAL encadeado por sequência e SHA-256; não contém mutação nem revisão observada |

O código de comparação de 10 hex, nonce de prova, JWT, token CSRF e chaves privadas não devem ser persistidos. O nonce é consumido após prova. A comparação do código e o owner gate ficam em `owner-pairing-review.mjs`; JWT/CSRF e o `ownerId` derivado ficam em `owner-pairing-http.mjs`.

### Ordem e repetição observadas

O handler cria um eventId, grava `intent`, então chama o review que valida request pendente, prova, fingerprint e código, e só então chama `approvePairing()`. O trust store cria o deviceId e persiste a revisão antes do WAL `outcome`. A fila `decisionQueue` serializa decisões dentro do handler; o lock de diretório do audit WAL exclui outros escritores/processos. `advance()` impede um segundo intent com pendência e outcomes órfãos/duplicados.

Cada request HTTP é tratado uma vez. A aprovação consome o pedido pendente após o trust commit. Falha de intent impede mutação; falha de outcome retorna 503 e envenena o handler, pois a mutação pode já ter ocorrido. Não há retry automático da transição de trust.

### Durabilidade, locks e restart observados

- Trust escreve arquivo temporário exclusivo com modo 0600, `fsync` do arquivo, rename atômico e `fsync` do diretório. `.trusted-devices-writer.lock` é criado por `mkdir` antes de gravar; falhas incertas retêm o lock. Lock preexistente nunca é roubado. Instâncias verificam identidade do diretório, revisão/conteúdo e lock em operações de autorização.
- Audit valida diretório/arquivo privados, cadeia de hash, sequência, limites de bytes/linha e newline final. Append é posicional e `fsync` antes de responder sucesso. `.owner-decisions-writer.lock` é exclusivo e removido apenas no `close()` saudável. Inicialização recusa lock existente, WAL truncado/corrompido e intent pendente.
- Restauração do trust cria registry novo sem sessões, desafios ou presença online. Mudança de revisão invalida a facade antiga; revogação também remove sessões/challenges.
- Depois de crash, locks persistentes bloqueiam inicialização. O WAL identifica intent pendente, mas não pode provar sozinho se trust mudou. O trust snapshot prova seu estado, mas não a qual decisão auditada uma mutação pertence. Pairing pendente é efêmero e não é evidência após restart.

### Invariantes implementados para I2B–I2E

1. O audit WAL v2 preserva `eventId`, requestId literal, fingerprint e revisões; resultado de aprovação acrescenta deviceId. Registros v1 continuam legíveis sem inferir campos ausentes.
2. O trust snapshot v2 contém um baseline `{deviceId, fingerprint}`, histórico estrito e limitado de transições e o conjunto atual de devices. O leitor reaplica todas as transições ao baseline e exige que o resultado seja exatamente igual ao conjunto atual. Uma aprovação acrescenta device e recibo `{eventId, requestId, fingerprint, deviceId, previousRevision, revision}` na mesma substituição atômica do snapshot.
3. A facade mantém aberto um descritor do diretório de trust durante sua vida e compara o descritor com o caminho nomeado em cada operação. Isso impede que a substituição rápida de um diretório vazio passe por reutilização de inode/birthtime; `close()` libera o descritor e invalida a facade. A mutação exige a revisão esperada e rejeita reutilização de eventId/requestId; nenhuma autorização é aplicada por replay de intent.
4. A análise de recuperação não grava. A reconciliação requer que o operador pare e confirme a ausência de todos os processos que podem escrever nos dois diretórios; depois instala locks de recuperação, revalida as evidências e só completa uma aprovação se o recibo e as revisões coincidirem exatamente. Uma aprovação sem recibo e com a revisão inalterada recebe `not_applied`, sem replay. Intent de rejeição sem recibo fica `EPHEMERAL_RESULT_UNKNOWN`, pois o WAL e a revisão de trust não provam se a entrada efêmera foi removida antes do crash.
5. Divergência, corrupção, histórico incompleto, intent legado pendente, rejeição efêmera desconhecida ou arquivo temporário de trust sem seu lock permanecem bloqueados. Registros v1 completos são classificados `LEGACY_UNBOUND`; não recebem vínculo retroativo.
6. Lock persistente não é removido na inicialização. A chamada explícita de reconciliação exige a trava de recuperação e confirmação de quiescência para liberar locks de WAL/trust após validação. Uma trava de recuperação abandonada só pode ser limpa por chamada explícita que confirma ausência de reconciliador ativo. Nenhum caminho chama a operação de aprovação.

### Recuperação e limites

`analyzeOwnerPairingRecovery({auditDirectory, trustDirectory})` é somente leitura. Para reconciliar, o operador precisa parar todos os processos que poderiam escrever nos diretórios de audit e trust e então invocar `reconcileOwnerPairingRecovery({auditDirectory, trustDirectory, operatorConfirmedNoActiveWriters: true})`. Esse parâmetro representa uma confirmação operacional, não uma detecção automática de processos. A rotina revalida WAL, snapshot e locks enquanto mantém os locks de recuperação.

`not_applied` significa que nenhuma mutação durável de trust ocorreu para aquela aprovação; não significa que um pedido de rejeição efêmero não tenha sido removido. A rotina nunca reaplica aprovação ou rejeição. Rejeições com outcome ausente permanecem bloqueadas para intervenção, porque o estado de pairing é somente memória e não sobrevive ao restart.

Estados principais do diagnóstico: `NO_INTENT`, `INTENT_NOT_APPLIED`, `COMMITTED_OUTCOME_MISSING`, `CONSISTENT`, `LEGACY_UNBOUND`, `EPHEMERAL_RESULT_UNKNOWN`, `REVISION_DIVERGED`, `OUTCOME_CONTRADICTS_TRUST`, `TRUST_RECEIPT_WITHOUT_AUDIT`, `TRUST_HISTORY_INCOMPLETE`, `ORPHAN_TRUST_TEMP`, `RECOVERY_LOCK_PRESENT` e `CORRUPT`. Arquivos `.trust-*` são limitados, validados e limpos apenas sob lock persistente de trust e reconciliação explícita; sem lock writer correlato, não são removidos automaticamente.

O handler segue inerte e fora de `gateway/server.mjs`; este trabalho não ativa endpoint nem pareamento live.
