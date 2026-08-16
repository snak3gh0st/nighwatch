# AgentSec

CLI Linux-first para usar AI como copiloto de bug bounty e security testing em ativos onde existe autorização explícita.

O AgentSec não é um scanner que dispara centenas de templates. A proposta é combinar:

1. observações da aplicação;
2. raciocínio do modelo local via Ollama;
3. ferramentas determinísticas;
4. validação independente;
5. evidências reproduzíveis;
6. relatório final revisável por uma pessoa.

A regra principal é: o modelo pode propor uma próxima tarefa, mas nunca recebe acesso direto à rede, browser, shell ou ferramentas. Qualquer execução futura terá de passar pelo Tool Gateway, Scope Guard, Rate Limiter, Request Logger e Action Approval.

## O que ele faz hoje

Este primeiro slice já implementa o núcleo seguro:

- configuração de um engagement autorizado;
- escopo default-deny por esquema, host, porta, path e método HTTP;
- hosts excluídos explicitamente;
- hash determinístico da política;
- limites de requests, concorrência e custo;
- classificação de ações como `read_only`, `state_change` ou `destructive`;
- redaction de headers e parâmetros sensíveis;
- cliente Ollama local com JSON estruturado;
- Planner Agent que propõe uma única próxima tarefa;
- Tool Gateway em modo `dry-run`;
- testes unitários da camada de segurança.

Ainda não há execução real de HTTP, browser, shell, Nuclei, ffuf ou outros scanners. Isso é intencional. A primeira etapa valida o contrato de autorização e o fluxo de raciocínio antes de adicionar ferramentas que gerem tráfego.

## Strix upstream

O motor de pentesting e reporting do Strix foi importado em [`vendor/strix/`](vendor/strix/). A integração ainda está atrás do AgentSec e não é executada automaticamente nesta fase.

Vamos reutilizar do Strix:

- agentes e coordenação multi-agent;
- runtime Docker e sandbox;
- proxy/Caido e histórico de requests;
- skills de vulnerabilidades;
- geração de PoCs e reports;
- JSON, CSV, SARIF e Markdown.

O AgentSec adicionará a fronteira que o Strix não deve receber diretamente: escopo tipado, aprovação, rate limit, receipts, Evidence Store e verificação independente. A decisão de integração está documentada em [`docs/STRIX_INTEGRATION.md`](docs/STRIX_INTEGRATION.md), e a licença do código importado em [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Como ele ajudará no bug bounty

Quando o pipeline estiver completo, o fluxo será:

```text
escopo autorizado
  -> recon controlado
  -> mapa da aplicação
  -> análise de autenticação
  -> comparação entre perfis de usuário
  -> hipóteses de autorização, API e business logic
  -> execução limitada de testes
  -> observação dos resultados
  -> validação independente
  -> evidência reproduzível
  -> análise de impacto
  -> relatório
```

O modelo será útil principalmente para:

- relacionar endpoints, objetos, papéis e fluxos de negócio;
- comparar respostas entre `owner_user`, `non_owner_user` e outros perfis autorizados;
- sugerir hipóteses de IDOR/BOLA, broken access control, API authorization, SSRF, XSS e falhas de sessão;
- decidir qual observação falta para confirmar ou rejeitar uma hipótese;
- transformar evidências já coletadas em uma reprodução e relatório claros.

Ele não deve declarar uma vulnerabilidade apenas por probabilidade textual. O finding precisa ter evidência observável, reprodução consistente e impacto demonstrável.

## Requisitos

- Python 3.12 ou superior;
- Ollama instalado localmente;
- um modelo local compatível com chat e structured outputs;
- autorização escrita para cada target testado.

O código usa apenas a biblioteca padrão em runtime neste estágio. Isso facilita a auditoria do núcleo antes da entrada de browser, HTTP clients e scanners.

## Instalação

```bash
git clone <url-do-repositorio>
cd agentsec

python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[dev]'
```

Valide a instalação:

```bash
agentsec --version
pytest
```

Se o entrypoint ainda não estiver disponível no shell, execute a CLI diretamente a partir do código-fonte:

```bash
PYTHONPATH=src python -m agentsec.cli --help
```

Ao abrir um terminal interativo, o CLI exibe a identidade `NIGHTWATCH // AGENTSEC`, atribuída a `snak3gh0st`. O comando original `agentsec` continua disponível e `nightwatch` é um alias de entrada:

```bash
nightwatch --help
agentsec --no-banner scope validate --config engagements/example.json
```

O banner vai para `stderr`, portanto não quebra JSON em `stdout` nem pipelines. Use `--no-banner` em automações.

## Configurar o Ollama

No Mac Apple Silicon, o Ollama pode usar a aceleração Metal. No Linux, ele pode usar CPU ou a GPU disponível. Para o MVP, mantenha o Ollama no mesmo host da CLI e não exponha a API para a rede.

Inicie o serviço, caso ainda não esteja ativo:

```bash
ollama serve
```

Baixe um modelo adequado para uma máquina com 24 GB de memória:

```bash
ollama pull qwen2.5-coder:14b
```

Configure o modelo:

```bash
export AGENTSEC_OLLAMA_MODEL=qwen2.5-coder:14b
export AGENTSEC_OLLAMA_TIMEOUT_SECONDS=180
export AGENTSEC_OLLAMA_MAX_TOKENS=512
```

Teste a conexão:

```bash
agentsec llm health
```

O cliente usa `http://127.0.0.1:11434` por padrão e recusa endpoints remotos. Essa decisão evita transformar o modelo em um serviço acessível por outros dispositivos sem uma configuração explícita.

Modelos maiores podem ser usados para análise offline mais profunda, mas consomem mais memória e podem competir com Chromium, proxy e ferramentas de recon. Em um M4 Pro com 24 GB, comece com um único modelo de aproximadamente 14B.

## Criar um engagement autorizado

Crie um diretório local. Arquivos de engagement, evidências e secrets são ignorados pelo Git porque podem conter autorização, tokens ou PII.

```bash
mkdir -p engagements
agentsec init --output engagements/example.json
```

Edite o arquivo e substitua os placeholders apenas pelos dados do programa autorizado. O campo `authorization.artifact_id` é uma referência ao documento ou ticket de autorização; ele não deve conter o documento nem credenciais.

Exemplo mínimo seguro:

```json
{
  "engagement_id": "eng_acme_2026_001",
  "authorization": {
    "artifact_id": "bbp-program-scope-2026-001"
  },
  "allowed_origins": [
    {
      "scheme": "https",
      "host": "authorized.example.com",
      "ports": [443],
      "path_prefixes": ["/api/"],
      "methods": ["GET"]
    }
  ],
  "excluded_hosts": [
    "admin.authorized.example.com"
  ],
  "auth_profiles": [
    "owner_user",
    "non_owner_user"
  ],
  "limits": {
    "requests_per_second": 1.0,
    "max_requests": 100,
    "max_concurrent_requests": 1,
    "max_cost_usd": 1.0
  },
  "actions": {
    "read_only": true,
    "state_mutation": false,
    "destructive": false
  }
}
```

Regras importantes:

- não use wildcard de domínio;
- declare esquema, host, porta, path e métodos de forma explícita;
- não coloque cookies, API keys, senhas ou tokens no JSON;
- comece apenas com `GET` e `read_only`;
- não inclua subdomínios fora do programa;
- trate a política do programa como uma restrição executável, não como texto para o prompt.

## Validar o escopo antes de qualquer teste

```bash
agentsec scope validate --config engagements/example.json
agentsec policy --config engagements/example.json
```

Teste uma URL individual:

```bash
agentsec scope check \
  --config engagements/example.json \
  --method GET \
  --url https://authorized.example.com/api/health
```

O comando retorna código `0` quando a URL está autorizada e código `2` quando é rejeitada. Uma URL com outro host, porta, método ou path deve ser recusada.

O hash exibido em `scope validate` e `policy` identifica a política efetiva usada para a execução. Ele deve acompanhar os receipts e as evidências quando o executor real for implementado.

## Ver o plano seguro

O comando abaixo não faz uma requisição. Ele apenas mostra o que seria avaliado pelo gateway:

```bash
agentsec run \
  --config engagements/example.json \
  --dry-run
```

Sem `--dry-run`, a execução termina bloqueada nesta fase:

```text
execution blocked: the HTTP/browser/shell Tool Gateway is not enabled yet
```

## Usar o Planner com Ollama

Uma observação é um arquivo de texto contendo fatos já observados por uma pessoa ou ferramenta autorizada. Ela pode incluir endpoints, status, headers não sensíveis, diferenças de resposta e contexto do fluxo. Remova tokens, cookies, PII desnecessária e segredos antes de salvar.

Teste com a observação sintética incluída no repositório:

```bash
agentsec plan \
  --config engagements/example.json \
  --observation examples/observations/order-api.txt \
  --model qwen2.5-coder:14b
```

O resultado contém campos semelhantes a:

```json
{
  "task_kind": "analyze_authentication",
  "target_ref": "endpoint:ep_orders_get",
  "reason": "determine the authentication requirements",
  "auth_profiles": ["owner_user", "non_owner_user"],
  "expected_evidence": ["authentication mechanism", "access-control behavior"],
  "risk_level": "read_only",
  "confidence": 0.8,
  "approval_required": false
}
```

`target_ref` é um identificador opaco, não uma URL executável. A proposta não autoriza rede, não confirma uma vulnerabilidade e não substitui a revisão humana.

## Fluxo recomendado durante um teste

1. Obtenha e arquive a autorização escrita e as regras do programa.
2. Crie um engagement separado por programa ou target.
3. Declare somente hosts, paths e métodos permitidos.
4. Valide a configuração e registre o `policy_hash`.
5. Colete uma observação inicial de forma manual ou com uma ferramenta autorizada.
6. Peça ao Planner uma única próxima tarefa.
7. Revise a proposta antes de executá-la.
8. Execute somente através do Tool Gateway quando essa camada estiver habilitada.
9. Guarde request, response, perfil de autenticação, timestamp e hash da evidência.
10. Reproduza o comportamento de forma independente antes de criar o finding.
11. Demonstre impacto sem alterar dados reais ou causar indisponibilidade.
12. Gere o relatório final somente com evidência verificável.

O pipeline de findings será:

```text
Candidate Finding
  -> Verification
  -> Independent Reproduction
  -> Evidence Collection
  -> Impact Analysis
  -> Final Finding
```

## Arquitetura de segurança

```text
Humano + autorização
          |
          v
EngagementConfig -> Scope Guard -> Rate Limiter -> Action Approval
          |                              |
          v                              v
     Ollama Planner                 Tool Gateway
          |                       (futuro HTTP/browser/shell)
          v                              |
     Task Proposal ----------------------+
                                         v
                              Request Logger + Evidence Store
```

O modelo fica no plano de decisão. As ferramentas ficam no plano de execução. Essa separação é necessária para reduzir prompt injection, escopo acidental, falsos positivos e ações destrutivas.

## O que ainda será implementado

As próximas camadas serão adicionadas nesta ordem:

1. Evidence Store com hashes e receipts imutáveis;
2. HTTP Tool read-only com egress pinning e rate limit;
3. adapter AgentSec -> Strix com instruction file limitado;
4. coleta de mapa da aplicação;
5. perfis autenticados e comparação de respostas;
6. Playwright controlado para fluxos web;
7. adapters para `httpx`, `katana`, `subfinder`, `nuclei` e `ffuf`, sempre atrás do gateway;
8. validação de findings e reprodução independente;
9. geração de relatório final.

Ferramentas tradicionais serão fontes de observação, não a autoridade final. O LLM não poderá executar um comando arbitrário nem converter uma saída de scanner diretamente em finding.

## Segurança e autorização

Use este projeto somente em ativos para os quais você possui autorização explícita. Leia [`SECURITY.md`](SECURITY.md) antes de adicionar qualquer adapter.

O MVP bloqueia execução real por design. Não tente contornar o bloqueio removendo o `dry-run`, relaxando o escopo ou expondo o Ollama na rede. Primeiro devem existir um gateway de egress, kill switch, approval flow, logging completo e Evidence Store.

## Troubleshooting

### `agentsec: command not found`

Ative o virtualenv ou use o fallback:

```bash
source .venv/bin/activate
PYTHONPATH=src python -m agentsec.cli --help
```

### Modelo não encontrado

```bash
ollama list
ollama pull qwen2.5-coder:14b
agentsec llm health --model qwen2.5-coder:14b
```

### Ollama não responde

```bash
ollama serve
agentsec llm health
```

Se a CLI estiver em uma VM Linux e o Ollama estiver no macOS host, prefira executar o Ollama dentro da mesma VM ou criar um encaminhamento local controlado. O AgentSec rejeita endpoints remotos por padrão.

### Planner muito lento

Use um modelo menor, mantenha uma única execução simultânea e limite o output:

```bash
export AGENTSEC_OLLAMA_MODEL=qwen2.5-coder:14b
export AGENTSEC_OLLAMA_TIMEOUT_SECONDS=180
export AGENTSEC_OLLAMA_MAX_TOKENS=512
```

## Licença e estado do projeto

O repositório está em fase inicial de desenvolvimento. Antes de usar em um programa real, revise o código, os termos do programa de bug bounty e o comportamento de cada ferramenta adicionada.
