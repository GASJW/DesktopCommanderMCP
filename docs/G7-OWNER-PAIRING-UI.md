# G7 — Revisão de pareamento por código na Dashboard (candidato inerte)

**Objetivo:** replicar a experiência visual de pareamento por código do RDC, **sem usar qualquer servidor do RDC/Supabase**. Este PR contém somente a página de revisão e um módulo de domínio com checagens de segurança. **A tela ainda não é disponibilizada pela Dashboard G6 e o comando `vpsc-agent pair` não existe no CLI instalado. Não há pareamento remoto ativo.**

## Fluxo futuro

1. Agente em usuário padrão, com identidade Ed25519 protegida localmente pelo DPAPI/0600, pede pareamento no ingresso HTTPS de máquina autenticada.
2. `pairing.mjs` existente gera `requestId`, nonce e **código comparativo de 10 caracteres hexadecimais** (ex.: `A1B2 C3D4 E5`; **somente exemplo**), com TTL de 2 minutos e prova Ed25519.
3. Proprietário entra na futura página `/dashboard/pairing`, acessível apenas após validação real da identidade do **owner** via Access JWT; o Gateway entrega lista sem código, e o proprietário digita aquele visto no dispositivo físico e confere o fingerprint.
4. Serviço de revisão `gateway/dashboard/owner-pairing-review.mjs` só aprova após **ownerGate autorizado, prova Ed25519 válida, fingerprint idêntico e código idêntico**; cinco erros cancelam a solicitação. Código sozinho não autentica agente nem proprietário.
5. Aprovação cria dispositivo confiável **offline**; só outro handshake autenticado torna o dispositivo online. Root/Admin (inclusive duração indefinida) é concessão posterior **separada** e não é resultado automático de pareamento.

## O que existe nesta branch

- `gateway/dashboard/owner-pairing-review.mjs`: serviço de domínio inerte, requer `ownerGate` explícito (default deny), permite listar campos não secretos, aprovar com código digitado/fingerprint/prova e rejeitar. Evita devolução do código ou nonce para a UI. Não representa uma API HTTP pronta.
- `gateway/dashboard/pairing.html`, `pairing.css`, `pairing.js`: protótipo visual consistente com o painel em grafite. Prevê listagem, fingerprint e preenchimento do código, mas controles ficam desativados se **não houver API autenticada com `enabled:true` e CSRF**. Sem dados reais, mostra indisponibilidade em vez de gerar códigos fictícios.
- Testes de assinatura versus código, autorização do proprietário, tentativas erradas, rejeição, expiração, dados não secretos e UI fail-closed.
- **Não há alteração em `gateway/server.mjs`, `gateway/dashboard/http.mjs`, Cloudflare, DNS, systemd ou npm. A rota ainda não está registrada.**

## Antes de disponibilizar

1. Implementar o `vpsc-agent pair` de verdade no dispositivo, com ingress de agente HTTPS autenticado (Cloudflare Access Service Auth independente), e request/response seguros. `doctor` instalado no Gui-PC não pode ser confundido com pareamento.
2. Montar a API owner-only com verificação da JWT Access do dono (não usar token de máquina), proteção CSRF contra requisições de outra origem, limitação de tentativas e auditoria durável de cada decisão. O Gateway atual rejeita qualquer header Origin e aceita GET/HEAD somente em Dashboard; não ativar POST sem redesenhar essa proteção.
3. Conectar à persistência confiável/revogação do Gateway; PR #21 está Draft por gates de single-writer, crash recovery, lock e auditoria. Não usar o registry volátil para admitir produção.
4. Tratar pairing approval, expiração e reconexão após restarts, rate limits, UX de revogação e reset. Não expor `displayCode` na API owner pending, para forçar comparação com a tela física.
5. Rodar testes reais de dispositivo ⇄ VPS, rotas de owner/agent isoladas, Cloudflare policies e rollback, antes de habilitar qualquer serviço ou privilégio.

O código de comparação atual tem **10 caracteres hexadecimais**; exemplo anterior de seis dígitos no diálogo era apenas ilustrativo. A revisão deve manter o formato existente ou migrá-lo explicitamente com compatibilidade/testes.

**Não é uma página live.** Não oferecer `/dashboard/pairing` como acessível até G7 ser integrado, auditado, publicado e validado. O G6 e o RDC continuam íntegros.
