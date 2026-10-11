# VPS Commander — arquitetura e implantação V0

Estado: FOUNDATION / NÃO PUBLICADO. Data: 2026-10-10.

## Objetivo
Substituir a dependência do relay e das cotas do Remote Desktop Commander por executor MCP open source na VPS, acessível tanto pelo ChatGPT (MCP personalizado) quanto por cliente web próprio opcional. Sem custo incremental de API por padrão. VPS, ChatGPT Plus e domínios existentes já são pagos.

## Infraestrutura verificada (Cloudflare API)
- Conta Cloudflare: 0402f34219e7269c01ea2fe3a8677ef7.
- Domínios ativos em Free Website: supercerebro.me e meucofre.app.
- Túnel existente: cofre (healthy) — NÃO ALTERAR.
- Aplicações Access existentes incluem Pantheon, OpenMausBot, Codex VPS Desktop e Maestro — NÃO ALTERAR.
- Túnel dedicado criado: vps-commander, UUID 9a11c3d5-cc76-4427-a6d6-b85722f0e4db, config_src=cloudflare, status=inactive. Sem rota DNS ou hostname, sem token em Git.
- Hostname sugerido, não provisionado: commander.supercerebro.me.

## Decisões arquiteturais
1. Reaproveitar DesktopCommanderMCP sob MIT; preservar LICENSE e origem upstream.
2. Não usar mcp.desktopcommander.app; usar transporte MCP Streamable HTTP padrão dentro de servidor/gateway próprio.
3. Cloudflare Tunnel nomeado + Access/OAuth compatível com ChatGPT; garantir proteção também no origin. Não publicar o shell sem autenticação validada.
4. Permitir comandos shell arbitrários ao usuário do executor, mas NÃO rodar como root ou montar docker.sock indiscriminadamente. Sudo administrativo separado e auditável.
5. Isolar serviço, storage e runtime de Pantheon, Hermes e OpenMausBot.
6. Sem operações na VPS nem deploy até verificação do runtime e testes de segurança. Sem RDC na implantação.
7. Credenciais fora de Git e Notion; usar secret store local com 0600.
8. Preferir versão fixa/dependências travadas em vez de latest no servidor.

## Sequência de certificação
- G0: documentação, branch, testes estáticos e verificação upstream;
- G1: serviço local somente loopback em VPS, ferramentas MCP operantes e logs limpos;
- G2: Cloudflare Tunnel e Access/OAuth autenticado e teste de negativa para usuário não autenticado;
- G3: conectar ChatGPT, testar ping e comando inofensivo;
- G4: escrita em workspace temporário, sessões e arquivos;
- G5: política explícita de elevação para systemd/Docker/PostgreSQL, auditoria e rollback.

## O que NÃO está concluído
- Nenhum código de gateway publicado em produção.
- Nenhum cloudflared configurado na VPS.
- Nenhuma rota DNS/Access nova.
- Nenhum plugin MCP do ChatGPT conectado.
- Nenhum privilégio root concedido.

## Custos
Cloudflare Tunnel / Zero Trust Free podem ser usados sem custo incremental nos limites atuais; não é promessa de condições vitalícias. IA pelo ChatGPT Plus é sujeita à franquia. API OpenAI tradicional não está habilitada neste projeto.

## Fontes
- https://github.com/wonderwhy-er/DesktopCommanderMCP
- https://github.com/wonderwhy-er/DesktopCommanderMCP/blob/main/SECURITY.md
- https://developers.cloudflare.com/tunnel/
- https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/secure-mcp-servers/

## Progresso de implementação 2026-10-10
- Gateway MCP HTTP para executor stdio implementado em `gateway/server.mjs`, bind forçado a loopback e autenticação bearer obrigatória.
- Testes isolados versionados em `gateway/test/gateway.test.mjs` com mock em `gateway/test/fixtures/mock-executor.mjs`.
- GitHub Actions: `VPS Commander Gateway Tests` GREEN em https://github.com/GASJW/DesktopCommanderMCP/actions/runs/38087630397 (teste com simulação, não VPS real).
- Guia local: `gateway/README.md`.
- DNS `commander.supercerebro.me`: sem registro existente na verificação, permanece NÃO CRIADO.
- Bloqueador crítico: o bearer estático do protótipo não é OAuth Access. Adicionar Managed OAuth para aplicativo MCP + validar JWT Cloudflare no origin (assinatura JWKS, emissor, audiência, expiração), conforme https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/ .
- Nenhuma instalação ou mutação na VPS e nenhuma chamada RDC realizada nesta etapa.
- PR continua Draft. Não publicar hostname/serviço antes de falha fechada com testes reais de autorização.
