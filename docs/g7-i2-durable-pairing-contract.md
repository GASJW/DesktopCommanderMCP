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
4. A análise de recuperação não grava. A reconciliação requer que o operador pare e confirme a ausência de todos os processos que podem escrever nos dois diretórios; também exige locks de processo persistentes e prova Linux de que os owners dos locks de WAL/trust terminaram. Depois instala locks de recuperação vinculados ao PID, boot ID e início do processo, revalida as evidências e só completa uma aprovação se o recibo e as revisões coincidirem exatamente. Locks ativos ou sem identidade verificável bloqueiam a operação. Uma aprovação sem recibo e com a revisão inalterada recebe `not_applied`, sem replay. Intent de rejeição sem recibo fica `EPHEMERAL_RESULT_UNKNOWN`, pois o WAL e a revisão de trust não provam se a entrada efêmera foi removida antes do crash.
5. Divergência, corrupção, histórico incompleto, intent legado pendente, rejeição efêmera desconhecida ou arquivo temporário de trust sem seu lock permanecem bloqueados. Registros v1 completos são classificados `LEGACY_UNBOUND`; não recebem vínculo retroativo.
6. Lock persistente não é removido na inicialização. A chamada explícita de reconciliação exige a trava de recuperação e confirmação de quiescência para liberar locks de WAL/trust após validação. Cada lock novo guarda schema v1 com PID, UID, boot ID, início do processo e token aleatório; não guarda credenciais nem material de pareamento. A criação e remoção de locks são serializadas por um arquivo guard persistente e `flock` do Linux (`/usr/bin/flock`), evitando que dois limpadores removam um lock novo após uma substituição concorrente. Uma trava de recuperação abandonada só pode ser limpa por chamada explícita, confirmação operacional e prova de que seu owner terminou. Locks antigos vazios, inválidos ou impossíveis de verificar nunca são removidos automaticamente. Falha depois do início de uma escrita mantém as travas de recuperação para diagnóstico. Nenhum caminho chama a operação de aprovação.

### Recuperação e limites

`analyzeOwnerPairingRecovery({auditDirectory, trustDirectory})` é somente leitura. `operatorConfirmedNoActiveWriters: true` e `operatorConfirmedNoActiveRecovery: true` são declarações explícitas do operador; isoladamente, elas não provam quiescência. Os locks verificam a identidade Linux do processo que os criou, e os módulos de escrita bloqueiam novas mutações enquanto a trava de recuperação está presente. Ainda assim, o operador precisa parar os writers conhecidos e impedir que seus supervisores os relancem antes de invocar `reconcileOwnerPairingRecovery({auditDirectory, trustDirectory, operatorConfirmedNoActiveWriters: true})`. A rotina instala locks nas duas árvores, rejeita owners ativos ou desconhecidos e revalida WAL, snapshot e locks enquanto mantém essas travas.

`not_applied` significa que nenhuma mutação durável de trust ocorreu para aquela aprovação; não significa que um pedido de rejeição efêmero não tenha sido removido. A rotina nunca reaplica aprovação ou rejeição. Rejeições com outcome ausente permanecem bloqueadas para intervenção, porque o estado de pairing é somente memória e não sobrevive ao restart.

Estados principais do diagnóstico: `NO_INTENT`, `INTENT_NOT_APPLIED`, `COMMITTED_OUTCOME_MISSING`, `CONSISTENT`, `LEGACY_UNBOUND`, `EPHEMERAL_RESULT_UNKNOWN`, `REVISION_DIVERGED`, `OUTCOME_CONTRADICTS_TRUST`, `TRUST_RECEIPT_WITHOUT_AUDIT`, `TRUST_HISTORY_INCOMPLETE`, `ORPHAN_TRUST_TEMP`, `ACTIVE_WRITER`, `WRITER_LOCK_UNVERIFIED`, `RECOVERY_LOCK_ACTIVE`, `RECOVERY_LOCK_UNVERIFIED`, `RECOVERY_LOCK_PRESENT` e `CORRUPT`. Arquivos `.trust-*` são limitados, validados e limpos apenas sob lock persistente de trust e reconciliação explícita; sem lock writer correlato, não são removidos automaticamente.

## Procedimento operacional para recuperação

Este procedimento só foi testado em diretórios temporários descartáveis. Não foi executado em diretórios de produção. O reconciliador e a API Owner Pairing continuam fora de `gateway/server.mjs`; não existe ativação live neste PR.

1. Registre os caminhos absolutos e os dispositivos/inodes das árvores audit e trust. Use `analyzeOwnerPairingRecovery()` antes de qualquer ação. Guarde o diagnóstico, sequência/hash do WAL, revisão/digest do snapshot e listagem dos locks para a trilha do incidente.
2. Identifique todos os processos que podem carregar `owner-pairing-http.mjs`, `owner-pairing-review.mjs`, `durable-owner-audit.mjs`, `durable-trust.mjs` ou `owner-pairing-reconciliation.mjs`, incluindo harnesses e scripts de manutenção. Pare esses processos pelo supervisor que os iniciou e suspenda temporizadores, sockets, jobs e políticas de restart enquanto durar o atendimento. Não altere unidades produtivas como parte deste PR.
3. Confirme a ausência por duas fontes: lista de processos/argumentos conhecidos e descritores em `/proc/<pid>/fd` que apontem para os diretórios/arquivos audit ou trust. Se `/proc` ocultar processos, houver permissão negada, ou qualquer PID não puder ser classificado, a exclusividade é desconhecida e a reconciliação deve parar. Mantenha a barreira de lançamento ativa; o parâmetro booleano não substitui essa evidência operacional.
4. Execute a reconciliação somente no par exato de caminhos revisado. Ela adquire locks exclusivos nas duas árvores, revalida as evidências e recusa owner ativo ou não verificável. Os locks também fazem as operações dos módulos candidatos falharem enquanto a reconciliação está em andamento. Não remova manualmente locks de writer.
5. Após retorno bem-sucedido, rode novamente `analyzeOwnerPairingRecovery()` e confirme `NO_INTENT`, `CONSISTENT` ou `LEGACY_UNBOUND` conforme o caso; compare revisão e sequência/hash com as evidências anteriores e valide a relação `eventId/requestId/fingerprint/deviceId/revision` quando aplicável. Um status divergente não é sucesso operacional.
6. Se o processo morrer ou uma escrita reportar erro depois de começar, preserve os arquivos e locks. Primeiro determine que o PID registrado morreu; `analyzeOwnerPairingRecovery()` deve indicar lock de recuperação presente, e não ativo. Só então use `clearStaleOwnerPairingRecoveryLocks()` com confirmação do operador. Locks vazios/legados ou de identidade desconhecida não podem ser limpos por essa API. Em seguida, analise de novo antes de qualquer nova reconciliação.
7. Não existe rollback transacional entre WAL e trust. Em falha parcial, não apague snapshot, histórico, WAL ou locks e não reverta/reaplique a autorização. Se a análise retornar corrupção, contradição, revisão divergente, histórico incompleto ou resultado efêmero desconhecido, mantenha o serviço bloqueado e escale com o diagnóstico. Se um outcome completo tiver chegado ao disco antes de erro de `fsync`, a reanálise pode prová-lo; caso contrário, continua bloqueado.

Para um lock vazio ou com owner record incompleto (crash durante a própria aquisição), a API automática sempre bloqueia. O operador mantém o launch fence, demonstra ausência de descritores/PIDs com a busca em `/proc`, registra o estado bruto e o digest dos arquivos e move o lock inteiro para quarentena de evidência no mesmo filesystem. Esse passo é manual e só é permitido depois da confirmação independente de que todos os writers/reconciliadores terminaram e não podem ser relançados. Se houver conteúdo inesperado, owner record malformado sem evidência clara de crash de aquisição, ou incerteza de processo, não mova o lock: preserve o par de diretórios e escale para investigação.

### Limite da prova de exclusividade

Os metadados do lock provam se o processo que criou aquele lock continua ativo no mesmo boot e com o mesmo início de processo. Eles não enumeram todos os processos que poderiam importar os módulos, nem substituem a barreira no supervisor. A rotina de limpeza só remove locks cujo owner foi comprovadamente encerrado pelo `/proc`; `operatorConfirmedNoActiveRecovery: true` sem essa prova falha fechado. Se não for possível parar e inspecionar todos os writers conhecidos, mantenha o Gate C RED e não invoque a reconciliação.

O handler segue inerte e fora de `gateway/server.mjs`; este trabalho não ativa endpoint nem pareamento live.
