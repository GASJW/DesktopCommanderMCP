# G7.3 — Contrato de duração de acesso administrativo (candidato inerte)

**Decisão do proprietário:** a futura Dashboard oferecerá a opção **Indefinida (até revogação manual)** ao lado de **10 minutos**, **30 minutos** e **1 hora** para solicitar modo Linux root / Windows administrador no dispositivo escolhido.

## O que este PR entrega

- Um contrato puro de duração que aceita apenas quatro seleções explícitas e modela `within_window`, `expired`, `revoked`, `not_started` e `invalid`.
- Duração indefinida = `expiresAt: null`, não zero nem um prazo arbitrário, permanecendo revogável.
- Testes de fronteira, adulteração, expiração, revogação e entradas inválidas.
- O contrato **não autoriza acesso**: `within_window` só indica que o prazo seria válido *se* existir aprovação verificada. A autorização real depende de identidade owner, deviceId, escopo e verificação server-side por operação.

## Gate de implementação futuro

1. Na Dashboard, modo **Padrão** permanece default. Alteração para **Administrador/Root** exige dispositivo explicitamente selecionado, duração escolhida e confirmação do proprietário.
2. Um serviço separado emite grant **persistente e revogável**, atrelado ao deviceId e ao escopo de ações autorizadas. Indefinida significa *sem expiração automática*; não significa shell root irrestrito.
3. Revogação imediata e observável na Dashboard, com invalidade de grants anteriores e fencing em operações concorrentes. Logout, mudança de identidade, desvinculação do dispositivo e falhas de auditoria precisam negar acesso.
4. Agente padrão continua como usuário não privilegiado; helper administrativo isolado só executa ações allowlisted, com confirmação para operações sensíveis e trilha de auditoria. `npx` jamais deve executar scripts arbitrários como root.
5. Estado deve sobreviver a restart e ter testes de persistência, revogação, reautenticação, anti-replay, falhas de conexão e recuperação antes de ativar em produção.

## Limites e separação

Este PR **não** implementa Dashboard, root, endpoints, grants, conexão remota, distribuição npx ou alteração de serviço. Não tocar G6 produtivo, G5.2/PR #10, Cloudflare, cofre ou outras stacks. O módulo não é importado pelo Gateway atual. O G7.1/PR #15 segue independente.

O Codex CLI 0.161.0 está presente na VPS, mas `codex login status` como `vpscommander` indicou **Not logged in**. O trabalho segue pela conexão Commander autenticada, sem copiar credenciais da conta root ou eliminar o sandbox.
