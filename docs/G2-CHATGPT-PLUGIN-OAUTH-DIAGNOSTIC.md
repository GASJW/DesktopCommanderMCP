# G2 — Diagnóstico de cadastro do plugin ChatGPT (2026-10-10)

## Sintoma
Na criação de um plugin MCP pessoal pelo ChatGPT em `https://commander.supercerebro.me/mcp`, autenticação "OAuth", a interface mostrou:
> Algumas configurações do aplicativo foram rejeitadas. Verifique a URL do servidor ou o ID do túnel, o ícone e as configurações de autenticação e tente novamente.

Esse erro é genérico; **não demonstra por si só** se houve falha no OAuth, protocolo MCP, ferramentas, permissões da conta ou camada de criação de plugins do ChatGPT.

## Evidência de rede observada
- `https://commander.supercerebro.me/mcp` retorna **401** para chamadas não autenticadas e header `WWW-Authenticate: Bearer` com URL do metadata do recurso.
- `/.well-known/oauth-protected-resource/mcp` responde 200 e anuncia `resource=https://commander.supercerebro.me/mcp`, authorization server `https://plain-block-9a74.cloudflareaccess.com`.
- Discovery do issuer `https://plain-block-9a74.cloudflareaccess.com/.well-known/oauth-authorization-server` responde 200 com authorization/token/registration endpoints; OAuth code + PKCE S256 + refresh_token + `token_endpoint_auth_methods_supported` incluindo `none`.
- Não há anúncio `client_id_metadata_document_supported` = true, então **preferir DCR** em vez de CIMD.
- `POST /cdn-cgi/access/oauth/registration` com corpo intencionalmente inválido (`redirect_uris=[]`) devolveu 400 `invalid_client_metadata`, provando existência e validação do endpoint, sem criar cliente.
- Cloudflare Browser Integrity Check está `on` no domínio (configuração existente, **não alterada**). User-Agent `Python-urllib/3.12` recebeu Cloudflare **403 code 1010** na descoberta; User-Agent `curl/8.5.0`, `python-requests/2.32`, `ChatGPT` e `ModelContextProtocol/1.0` receberam 200. **Não há evidência ainda de que o ChatGPT usou o User-Agent bloqueado**; não enfraquecer a política WAF sem causalidade confirmada.

## Configuração sugerida no plugin pessoal
- Nome: `VPS Commander`.
- Conexão: `URL do servidor` → `https://commander.supercerebro.me/mcp`.
- Auth: OAuth.
- Em **Configurações avançadas do OAuth**, selecionar **Dynamic Client Registration (DCR)** explicitamente, não CIMD e não cliente manual sem ID.
- Authorization server base: `https://plain-block-9a74.cloudflareaccess.com`.
- Authorization URL: `https://plain-block-9a74.cloudflareaccess.com/cdn-cgi/access/oauth/authorization`.
- Token URL: `https://plain-block-9a74.cloudflareaccess.com/cdn-cgi/access/oauth/token`.
- Registration URL: `https://plain-block-9a74.cloudflareaccess.com/cdn-cgi/access/oauth/registration`.
- Scopes defaults: deixar vazio, caso a UI permita, porque o servidor não anuncia `scopes_supported`. Não inventar escopos.
- Não inserir bearer local, credencial do tunnel ou segredos neste diálogo.

## Próximo diagnóstico obrigatório caso persista
1. Capturar screenshot da expansão **Configurações avançadas de OAuth**, incluindo opções selecionáveis de DCR/CIMD e escopos.
2. Se continuar rejeitado, capturar resposta de rede do botão `Criar como plugin` no DevTools do Firefox, **sem compartilhar cookies, tokens ou headers Authorization**; obter HTTP status, código de erro e Request ID sanitizados.
3. Correlacionar com Cloudflare Security Events/WAF pelo horário e `Cf-Ray`; distinguir HTTP 1010 de erro da administração do ChatGPT.
4. Se necessário, certificar protocolo MCP com cliente OAuth real após login do proprietário; não suspender Access/JWT da origem e não expor shell anônimo.

## Referências
- https://developers.openai.com/api/docs/guides/custom-mcp-server
- https://developers.openai.com/plugins/build/auth
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/

**Status:** plugin ChatGPT NÃO criado; o gateway permanece protegido; PR Draft.
