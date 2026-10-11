## G2 — Certificação end-to-end GREEN (2026-10-10)

Testes REAIS via plugin personalizado Commander no ChatGPT, SEM RDC:
- start_process: VPS_COMMANDER_PLUGIN_TEST=GREEN; HOST=gui; USER=vpscommander; PWD=/opt/vps-commander/code/dist.
- read_file /etc/os-release: Ubuntu 24.04.4 LTS.
- write_file criou /var/lib/vps-commander/workspace/commander-plugin-smoke-20261010.txt.
- read_file de volta confirmou VPS_COMMANDER_PLUGIN_WRITE_GREEN, ORIGIN=CHATGPT_CUSTOM_MCP e HOST=gui.

Conclusão: autenticação OAuth, roteamento Cloudflare, MCP, terminal e operações de arquivos via conexão personalizada ChatGPT PASS. O usuário do processo permanece vpscommander, sem root.

Pendente em próximos gates: hardening, auditoria, privilégio administrativo governado e revisão para merge. PR Draft preservado.