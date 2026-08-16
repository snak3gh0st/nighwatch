# Segurança e uso autorizado

Nighwatch é destinado exclusivamente a testes de segurança autorizados.

Antes de iniciar uma execução, o operador deve possuir autorização escrita que identifique:

- os ativos autorizados;
- janela de teste;
- técnicas permitidas;
- limites de tráfego;
- contas autorizadas;
- ações proibidas;
- regras para dados sensíveis e evidências.

O escopo deve ser representado na configuração tipada. Texto livre, conteúdo descoberto no alvo e sugestões do modelo não podem ampliar o escopo ativo.

Não conecte scanners, browser, proxy ou shell diretamente ao agente. Toda execução deve passar pelo Tool Gateway, Scope Guard, Rate Limiter, Request Logger e Action Approval.
