# G5.2 — Backup criptografado no Google Drive (11/10/2026)

**Estado: implementação/teste isolado GREEN; upload real e restauração externa PENDENTES. Não declarar G5.2 final GREEN.**

## Destino criado na conta Google já conectada

- [VPS-Backups](https://drive.google.com/drive/folders/1AbY5wezHcdGu30kvxsR6nWp9VQYEXyeW)
- [VPS-Backups/Commander](https://drive.google.com/drive/folders/1G3ozCDJxKIhFG0P287c--RFWxeQ9Z_V0). Metadados do Drive: `shared=false`.
- O usuário informou espaço disponível de 5 TB no seu Google AI Pro. **Nenhum backup real foi enviado ainda.**

## Estado da VPS

- Ubuntu 24.04 gui, gateway, executor, Cloudflare Commander e túnel cofre continuam ativos.
- Instalados somente `age` 1.1.1 e `rclone` 1.60.1 pelos repositórios APT oficiais do Ubuntu, sem reiniciar os quatro serviços.
- Snapshot G5.1 root-only em `/var/backups/vps-commander/snapshot.7IuqlqY2`, TAR 1.198 bytes e manifesto SHA-256 preservados.

## Design de chave — requisito de segurança

- A chave privada real deve nascer **fora da VPS**, preferencialmente no Gui-PC, e ser guardada em cofre de senhas ou mídia offline. Nunca colocá-la em Drive, GitHub, Notion ou logs do ChatGPT.
- O Gui-PC estava offline na última verificação. O script `deploy/g5-keygen-windows.ps1` cria identidade local com ACL restrita, recusa sobrescrever e exibe apenas recipient PÚBLICO. **Não executado.**
- A VPS recebe somente o recipient público em `/etc/vps-commander-backup/recipients.txt`, owner root. Sem esse arquivo o backup real falha fechado.

## Implementação candidata na branch

- `deploy/g5-offsite-encrypt.sh`: root-only, valida o snapshot e digest, exige um recipient válido, criptografa via `age -R`, entrega ciphertext com modo 0600 e recibo. Não usa nem cria chave privada.
- `deploy/g5-offsite-upload.sh`: root-only; exige `rclone.conf` root:600, remote nomeado `vpscmdbackup`, `scope = drive.file` e `root_folder_id` explícito; copia com `--immutable`, compara SHA-256 via `rclone cat`, sem sync/delete.
- `deploy/g5-restore-verify.py`: rodar somente fora da VPS. Descriptografa em pasta temporária, inspeciona TAR e aceita apenas os quatro caminhos esperados, sem instalar serviços.
- `deploy/test/g5-offsite.test.mjs`: 5 verificações de sintaxe, isolamento da chave, permissão OAuth restrita, segurança da restauração e geração local Windows.

## Evidência criptográfica real, mas com dados SINTÉTICOS

Em pasta root temporária foram criados quatro arquivos de exemplo e um par `age` **de teste**. A identidade privada do teste foi descartada junto da pasta, sem usar a configuração real da VPS.

```text
G5_2_ENCRYPT=GREEN
G5_2_RESTORE_TEST=GREEN
G5_2_RESTORED_FILE_COUNT=4
G5_2_RESTORE_WRITES_TO_SYSTEM=NO
G5_2_ISOLATED_ENCRYPT_RESTORE=GREEN
G5_2_PRODUCTION_SNAPSHOT_UNTOUCHED=YES
```

Isso qualifica cifrar/decriptar e validar a estrutura, **não comprova envio ao Google Drive** ou restauração em outro equipamento. A tentativa de transferir um arquivo inofensivo usando o bridge de arquivos do ChatGPT falhou por sessão de container; não houve upload.

## OAuth e limitação do escopo drive.file

A conta Google conectada ao ChatGPT **não delega automaticamente OAuth** ao rclone na VPS. O consentimento separado do proprietário será necessário para execução autônoma.

Rclone com `scope=drive.file` só vê os arquivos e pastas criados pelo próprio rclone. Portanto, a pasta `Commander` criada pelo conector ChatGPT não será automaticamente visível. Após consentimento, o rclone deve criar sua subpasta e ela poderá ser movida para dentro de `VPS-Backups/Commander` pelo conector autorizado, preservando seu ID como `root_folder_id` (validar essa operação). Evitar escopo `drive` total. Referência: https://rclone.org/drive/.

## Próximas etapas e bloqueios

1. Gui-PC online: executar geração da chave e guardar identidade privada fora da VPS e do Drive; passar à VPS SOMENTE a chave pública.
2. Configurar o OAuth rclone específico com `drive.file` e pasta criada pelo próprio cliente (pode exigir cliente OAuth Google personalizado; client compartilhado está sendo descontinuado). Token de refresh root:600.
3. Criptografar snapshot real e enviar cópia imutável; comparar SHA-256 remoto sem descriptografar na VPS.
4. Baixar arquivo criptografado para Gui-PC e testar restauração fora da VPS com identidade privada; jamais extrair diretamente em `/`.
5. Só então certificar G5.2 GREEN e discutir retenção/rotina; nenhum timer criado.

**Gates restantes:** chave externa real; OAuth; upload; readback remoto; restore independente. A criptografia não torna os arquivos imutáveis contra exclusão por credencial comprometida.
