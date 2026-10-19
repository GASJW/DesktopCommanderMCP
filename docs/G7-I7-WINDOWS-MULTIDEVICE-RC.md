# G7 I7 — Windows agent e M2M multi-dispositivo (release candidate)

## Estado e limites

Este documento descreve o candidate `g7-i7-rc1` derivado da linha I5F. O agente não foi instalado como piloto persistente no Gui-PC e o candidate não foi implantado no Gateway ativo da VPS. Os testes usam estado descartável e servidores TLS locais. A configuração do Cloudflare, G6, containers e os stores persistentes da VPS ficam fora desta implementação.

O candidate mantém o Gateway com listener loopback. Para um piloto posterior, o agente Windows deve abrir uma conexão SSH local encaminhada e usar TLS com hostname e CA fixados. Não crie listener público nem inicialização automática no boot.

## O que muda

- O worker aceita `win32`, recusa execução elevada, protege identidade/segredos com DACL NTFS e DPAPI CurrentUser e mantém ledger com substituições NTFS write-through. ACLs amplas, arquivos com reparse point e leitura fora da raiz aprovada falham fechados.
- `scripts/g7-staging-device-pair.mjs` cria ou reabre a identidade persistente, envia a chave pública, prova posse e imprime somente request ID, código de comparação e fingerprint. `--binding-receipt` persiste a binding retornada pelo Owner com `bindApprovedDeviceIdentity`.
- Configuração Gateway v1 continua aceita para o único Client-ID existente. Configuração v2 usa `machine.clients[]`, com pelo menos dois Client-IDs e secrets distintos. Cada binding e grant aponta para um `deviceId`; chamadas MCP selecionam o destino explicitamente.
- `scripts/g7-staging-owner-provision.mjs --add-device` confere as revisões atuais fornecidas pelo Owner e faz uma única sequência de aprovação, binding e grant. Não limpa nem regrava stores. Timeout ou resposta ambígua exige reconciliação antes de qualquer nova tentativa.
- O agente reconecta com novo challenge e nova sessão apenas enquanto está ocioso. Se a entrega, execução, resultado ou cancelamento puder ter sido aceito sem confirmação, ele encerra a sessão e não repete a operação. Revogação ou rejeição de autenticação encerra o worker.

## Preparação para rollout aprovado

Faça estes passos somente depois da aprovação separada para rollout do candidate no Gateway. O procedimento não foi executado nesta release candidate.

1. Instale o candidate em um diretório de release versionado no VPS e mantenha a configuração v1 e os stores atuais. Atualize a configuração de máquina para v2 preservando o Client-ID e secret Linux existentes e adicionando um novo Client-ID/secret sintético exclusivo para Windows. Não copie credenciais do G6.
2. Reinicie somente o Gateway G7 durante o rollout aprovado e confirme que as revisões e a binding Linux existentes continuam iguais. O listener deve continuar em `127.0.0.1:18443`.
3. No Gui-PC, abra um PowerShell sem elevação e inicie o encaminhamento local:

   ```powershell
   ssh.exe -NT -o ExitOnForwardFailure=yes `
     -L 127.0.0.1:18444:127.0.0.1:18443 cofre-vps
   ```

   O alias `cofre-vps` deve apontar para a VPS gui. O túnel escuta somente em loopback no PC e encaminha para o listener loopback do Gateway.

4. Crie um diretório privado em `%LOCALAPPDATA%\VPSC\G7`. Remova herança ACL e conceda controle somente à conta Windows do piloto e a `SYSTEM`. Aplique a mesma DACL a `identity`, `ledger`, `approved-root`, configurações, CA e recibo do Owner. O worker recusará uma ACL mais ampla.
5. Crie `pairing.json` com estes campos estritos:

   ```json
   {
     "version": 1,
     "hostname": "g7-staging.test",
     "port": 18444,
     "caPath": "C:\\Users\\<user>\\AppData\\Local\\VPSC\\G7\\staging-ca.pem",
     "identityDirectory": "C:\\Users\\<user>\\AppData\\Local\\VPSC\\G7\\identity",
     "deviceName": "Gui-PC Windows pilot"
   }
   ```

   Grave a configuração e CA sem herança ACL, com leitura/escrita apenas para a conta do piloto e `SYSTEM`.

6. Execute o pareamento no Gui-PC:

   ```powershell
   node scripts/g7-staging-device-pair.mjs `
     --config "$env:LOCALAPPDATA\VPSC\G7\pairing.json"
   ```

   Compare request ID, código e fingerprint exibidos com a solicitação pendente no Owner. Aprove somente o fingerprint comparado. Para `--add-device`, informe as revisões trust, binding e policy lidas do Gateway e use o Client-ID Windows. O Owner CLI exige que essas revisões ainda correspondam antes de fazer qualquer mutação.

7. Salve o JSON de resultado do Owner como `owner-binding.json`, proteja-o com a DACL privada e aplique a binding à identidade Windows:

   ```powershell
   node scripts/g7-staging-device-pair.mjs `
     --config "$env:LOCALAPPDATA\VPSC\G7\pairing.json" `
     --binding-receipt "$env:LOCALAPPDATA\VPSC\G7\owner-binding.json"
   ```

8. Crie `agent.json` com versão 1, hostname `g7-staging.test`, porta `18444`, `deviceId`, Client-ID Windows, secret M2M Windows, diretórios de identidade/ledger/raiz aprovada, caminho para o `dist/index.js` local validado, chave pública de policy do Gateway, caminho da CA e `pollIntervalMs` entre 25 e 5000. Proteja o arquivo com DACL privada. Não coloque o secret em argumentos, variáveis de ambiente, logs ou Git.
9. Inicie manualmente o worker e valide os eventos `READY`, `ONLINE` e `RECONNECTED` se o túnel cair e voltar:

   ```powershell
   node packages/vpsc-agent/bin/g7-staging-worker.mjs `
     --config "$env:LOCALAPPDATA\VPSC\G7\agent.json"
   ```

   Faça a leitura MCP somente de um arquivo dentro de `approved-root`; confirme que outra identidade recebe `403` ao consultar esse caminho. Ctrl+C encerra o worker, fecha o executor local e preserva identidade, ledger e recibos.

## Pacote de rollout reproduzível

O artefato `g7-i7-rc1-<commit>.tar.gz` é construído do commit Git registrado no manifesto ao lado do pacote. Antes de qualquer rollout separado, transfira o pacote e o manifesto por SSH, valide o SHA-256 e inspecione o conteúdo. Exemplo no PowerShell do Gui-PC:

```powershell
$commit = "REPLACE_WITH_COMMIT_SHA_FROM_MANIFEST"
$artifact = "<caminho-local>\g7-i7-rc1-$commit.tar.gz"
Get-FileHash -Algorithm SHA256 $artifact
scp.exe $artifact "cofre-vps:/var/tmp/g7-i7-rc1-$commit.tar.gz"
scp.exe "${artifact}.sha256" "cofre-vps:/var/tmp/g7-i7-rc1-$commit.tar.gz.sha256"
```

No VPS, compare o hash com o manifesto e extraia em um diretório imutável da versão. Preserve o destino atual de `current` e faça backup protegido da configuração antes de substituí-la:

```sh
set -eu
commit=REPLACE_WITH_COMMIT_SHA_FROM_MANIFEST
archive=/var/tmp/g7-i7-rc1-$commit.tar.gz
release=/opt/vps-commander/g7-staging/releases/g7-i7-rc1-$commit
current=/opt/vps-commander/g7-staging/current
config=/etc/vpsc-g7-staging-gateway/gateway.json
backup=/etc/vpsc-g7-staging-gateway/gateway.json.before-g7-i7-rc1
(cd /var/tmp && sha256sum -c "g7-i7-rc1-$commit.tar.gz.sha256")
test -L "$current"
readlink -f "$current"  # registre para rollback
sudo test ! -e "$release"
sudo test ! -e "$backup"
sudo install -d -o root -g root -m 0755 "$release"
sudo tar --no-same-owner -xzf "$archive" -C "$release"
sudo cp -a "$config" "$backup"
```

Somente depois de autorização separada, prepare `gateway.json` v2 preservando Owner, TLS, JWKS, signing key, storage e o Client-ID/secret Linux atuais. Adicione o Client-ID Windows e um secret sintético novo e distinto. Pare apenas os dois serviços G7, troque a symlink de versão atomicamente, instale a configuração com o owner e o modo atuais, inicie o Gateway e valide `/healthz` com a CA de staging. Confirme que a binding Linux e os stores existentes continuam válidos antes de iniciar o agente Linux; faça o pareamento Owner do segundo dispositivo usando o procedimento acima e só então inicie manualmente o agente Windows pelo túnel SSH.

```sh
sudo systemctl stop vpsc-g7-staging-agent.service vpsc-g7-staging-gateway.service
sudo ln -sfnT "$release" "${current}.next"
sudo mv -Tf "${current}.next" "$current"
sudo systemctl start vpsc-g7-staging-gateway.service
# Validar health, revisões e binding Linux com a CA de staging antes de prosseguir.
sudo systemctl start vpsc-g7-staging-agent.service
```

O processo não habilita os units no boot. Não substitua, limpe ou edite stores de trust, binding, grants, audit, identity ou ledger.

## Rollback

- Pare somente o worker G7 com Ctrl+C. Se ele não encerrar, finalize somente o PID G7 observado. Em seguida encerre a janela do SSH tunnel. Não pare G6 nem outros processos.
- Preserve `%LOCALAPPDATA%\VPSC\G7`, incluindo identidade DPAPI, binding e ledger. Não apague, restaure snapshot ou edite manualmente stores do Gateway.
- Se o Gateway candidate tiver sido implantado em rollout posterior, pare somente serviços G7 e volte o executável/configuração para a release anterior preservando os stores. Não reverta revisões nem tente remover uma binding gravada manualmente. O Gateway v1 mantém o Client-ID Linux configurado; o Windows permanece desconectado até que uma versão multi-device seja novamente ativada.
- Para o rollback mecânico, use o destino `current` registrado antes do rollout: pare os dois units G7, restaure esse destino por uma symlink temporária seguida de `mv -Tf`, restaure a cópia `gateway.json.before-g7-i7-rc1` mantendo owner/modo e reinicie Gateway e agente G7. Preserve o diretório da release, a configuração do agente Windows, identidade DPAPI, binding, ledger e todos os stores Gateway; encerre manualmente apenas o worker Windows e o túnel.
- O rollback não altera Cloudflare, G6 ou workloads existentes. Não configure serviço Windows ou inicialização no boot neste piloto.

## Certificação registrada

A evidência da release deve identificar a revisão Git, checksum do pacote, resultado da suíte nativa Windows, regressões Linux, fluxo Owner em revisões não zero, leitura por cada dispositivo, negação cruzada e estado de G6/workloads. Testes sintéticos não comprovam o funcionamento do Cloudflare Access nem autorizam implantação na VPS.

### Evidência Windows

- Em Windows nativo, Node **v24.16.0**, a matriz de 83 testes (`worker`, `https-client`, `windows-security`, `identity-store`, `pairing`, `local-mcp-readonly`, CLI de pareamento e templates de serviço) fechou com **76 PASS / 0 FAIL / 7 SKIP**. O Desktop Commander instalado localmente executou leituras MCP reais sob a raiz aprovada.
- Os sete skips estão identificados no runner: cinco verificações específicas de modos/symlinks POSIX, a injeção de falha em directory `fsync` que resolve o descritor por `/proc`, e um teste de symlink POSIX do MCP. As equivalentes Windows passaram usando DACL NTFS, junction/reparse, substituição `MoveFileEx` write-through, DPAPI CurrentUser e encerramento forçado do processo seguido de recuperação do lock.
- A suíte Windows do `governed-executor` também havia passado com **44 PASS / 0 FAIL / 6 SKIP**; esse código não mudou nesta correção de harness. O CLI Owner executa no Gateway Linux, não no agente Windows, e foi coberto pela suíte Linux.
- A suíte HTTPS valida TLS, hostname/CA fixados, autenticação de máquina, replay e leitura por MCP contra fixture local. Ela não é uma sessão autenticada contra o Gateway ativo da VPS.

### Evidência Linux

- Com Node **v22.23.2** e o entrypoint real do Desktop Commander, a suíte integral de `gateway/` e `packages/` fechou com **492 testes / 485 PASS / 0 FAIL / 7 SKIP**. Incluiu o Gateway multi-device, CLI Owner aditivo em revisões não zero, isolamento de grants/rotas, pairing e recuperação após restart/SIGKILL.
- Depois do ajuste do fixture Windows, `identity-store.test.mjs` foi repetido em Linux com **18 PASS / 0 FAIL / 1 SKIP**. O skip é somente DPAPI CurrentUser, indisponível em Linux.

O Gateway ativo continua em I5F e só autoriza o Client-ID Linux atual. Como este trabalho não pode implantar o candidate nem alterar a autenticação ativa, o handshake cruzado do Gui-PC com esse Gateway fica pendente do rollout multi-device aprovado. O caminho preparado usa SSH local forwarding e mantém o Gateway apenas em loopback.
