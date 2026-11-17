# IA de detecção de anomalias

Etapa **5. IA** da arquitetura (análise comportamental e detecção de anomalias). Lê a tabela de eventos da
camada Big Data ([BIG_DATA_EVENTOS.md](BIG_DATA_EVENTOS.md)), aponta as janelas de tempo com comportamento
anormal e grava cada alerta de volta na tabela como evento `anomalia`. O painel
([PAINEL_SEGURANCA.md](PAINEL_SEGURANCA.md)) lê esses alertas.

```
EventoSeguranca ──► features_por_janela() ──► regras de assinatura ─┐
   (Big Data)       (1 linha por IP e         Isolation Forest ─────┴─► evento `anomalia` ──► painel
                     janela de 5 min)
```

Código: `projeto/apps/deteccao_anomalias.py` (detector), `apps/management/commands/detectar_anomalias.py`
(comando), `apps/test_anomalias.py` (testes). Evidência: [`evidencias/07-ia-anomalias/`](../evidencias/07-ia-anomalias/).

## Resultado

| Abordagem (média de 5 sementes de validação) | Precisão | Recall | F1 |
|---|---|---|---|
| Só regras de assinatura | 1,000 | 0,813 | 0,896 |
| Só Isolation Forest | 0,836 | 0,769 | 0,800 |
| **Detector híbrido (o usado)** | **0,851** | **0,867** | **0,858** |

O híbrido encontra **5,4 pontos percentuais a mais de janelas anômalas** que as regras sozinhas, ao custo de
cerca de **5 falsos positivos por rodada de 50 mil eventos**. Todos esses falsos positivos ficaram com
pontuação abaixo de 0,70, então entram como `alerta` (para triagem) e nunca como `critico`.

As duas camadas se complementam. Nenhuma delas sozinha cobre todos os cenários:

| Cenário injetado (enunciado) | Janelas | Regras | Isolation Forest | Híbrido |
|---|---|---|---|---|
| Força bruta no login (tentativas de autenticação incomuns) | 40 | 78% | **88%** | 88% |
| Geração incomum de eventos | 41 | 61% | **76%** | 76% |
| Arquivo alterado (alterações inesperadas em arquivos) | 27 | **100%** | 37% | 100% |
| Rajada de falhas de decifragem | 34 | 94% | 91% | 94% |
| Varredura de acessos negados (padrão atípico de acesso) | 38 | 82% | 82% | 82% |
| Tráfego normal (falsos positivos) | 205.966 | 0 | 27 | 27 |

- **Onde o modelo ganha das regras:** nas bordas dos ataques. Uma força bruta que atravessa a fronteira entre
  duas janelas deixa, na segunda, só 3 a 8 falhas espalhadas por vários usuários, abaixo do limiar de 10 da
  regra. O mesmo vale para rajadas de 28 a 70 eventos, quando o limiar é 100. Nenhuma regra dispara, mas a
  combinação "muitos usuários + só falhas" é rara o bastante para o Isolation Forest isolar.
- **Onde as regras são indispensáveis:** arquivo alterado. São 2 a 6 eventos sem IP, um perfil pequeno demais
  para parecer raro estatisticamente. E uma única ocorrência já é incidente, não questão de grau.
- **O que nenhuma das duas pega:** fragmentos de ataque com menos de 3 eventos numa janela, que não vão ao
  modelo e ficam abaixo de qualquer limiar.

Saída completa das 6 rodadas: [`evidencias/07-ia-anomalias/resultado_avaliacao.txt`](../evidencias/07-ia-anomalias/resultado_avaliacao.txt).

## Como funciona

### 1. Entrada: features por janela

`analise_eventos.features_por_janela(5)`, da camada Big Data, agrupa os eventos por **entidade** (o IP de
origem ou, quando não há IP, o usuário) e por **janela de 5 minutos**. Cada linha traz o total de eventos, a
contagem de cada tipo (`login_falha`, `falha_decifragem`, `acesso_negado`, `integridade_violada`...), o número
de usuários distintos e a taxa de falha de login.

Ficam de fora os eventos `anomalia` (os próprios alertas da IA) e os resumos de ataque à cifra. Sem isso, cada
execução contaria os alertas da execução anterior como atividade daquele IP. Para isso foi acrescentado o
parâmetro opcional `excluir_tipos` em `features_por_janela`, sem mudar o comportamento de quem já a usava.

### 2. Camada de assinatura (regras)

Limiares fixos por janela de 5 minutos. Quando uma regra dispara, o alerta é `critico`.

| Regra | Limiar | Motivo |
|---|---|---|
| `integridade_violada` | ≥ 1 | Hash SHA-256 do arquivo não confere com o do upload |
| `login_falha` | ≥ 10 | Ordem de grandeza das políticas de bloqueio de conta |
| `falha_decifragem` | ≥ 10 | Uso legítimo quase nunca erra a chave |
| `acesso_negado` | ≥ 10 | Varredura de IDs (tentativa de IDOR) |
| `total` | ≥ 100 | Volume muito acima do normal de uma pessoa |

Os limiares foram fixados por critério de domínio, sem olhar o gabarito.

### 3. Camada comportamental (Isolation Forest)

O [Isolation Forest](https://scikit-learn.org/stable/modules/outlier_detection.html#isolation-forest) é um
algoritmo **não supervisionado**: não recebe exemplos de ataque, só aprende como os dados se distribuem. Ele
monta 300 árvores com cortes aleatórios. Um ponto raro é separado ("isolado") do resto com poucos cortes, e a
pontuação vem da profundidade média em que isso acontece. O resultado vai de 0 a 1: perto de 0,5 é comum,
perto de 1 é muito raro.

Decisões tomadas, todas medidas na semente de calibração (42):

| Decisão | Por quê |
|---|---|
| Só janelas com **≥ 3 eventos** vão ao modelo | ~97% das janelas têm 1 ou 2 eventos. Com todas elas, as rajadas de ataque se perdem no meio e o F1 cai para ~0,1. |
| Contagens em **log(1 + x)** | Uma rajada de 300 não pode achatar a escala de todas as outras features. |
| **Hora do dia fora** das features | Com ela, janelas normais de madrugada já parecem raras e disputam alertas com os ataques. F1 0,849 com hora e 0,914 sem, medido na calibração com a primeira versão do detector (Isolation Forest + só a regra de integridade). |
| **Contaminação 0,03** | Fração esperada de janelas suspeitas entre as que vão ao modelo. Testados 0,02, 0,03 e 0,04; 0,03 teve o melhor F1 na calibração. |
| `random_state=42` | Mesmo dado, mesmo resultado (há teste para isso). |

Alerta só do modelo é `alerta`, ou `critico` se a pontuação passar de 0,70.

**Explicação de cada alerta.** Um Isolation Forest não diz *por que* um ponto é raro. Para o alerta ser útil a
quem investiga, o detector calcula quanto cada feature daquela janela se afastou da média (z-score) e guarda as
3 maiores, com o valor observado e a mediana das janelas normais. Exemplo real de um alerta:
`login_falha = 154 (limiar 10)`, `usuarios_distintos = 43 (mediana 1)`.

### 4. Saída: evento `anomalia`

Cada janela suspeita vira uma linha na tabela `EventoSeguranca`, datada no início da própria janela:

| Campo | Conteúdo |
|---|---|
| `tipo` / `categoria` | `anomalia` |
| `severidade` | `critico` (regra ou pontuação ≥ 0,70) ou `alerta` |
| `ip` / `usuario` | a entidade suspeita |
| `origem` | `deteccao_anomalias` |
| `detalhes` | `metodo` (`regra`, `isolation_forest` ou ambos), `score`, `motivo`, `descricao`, `destaques`, `total_eventos`, `janela_inicio`, `id_janela`, e `cenario_simulado` (o gabarito, só em dado sintético) |
| `simulado` | `true` se a janela veio do gerador sintético (assim `gerar_eventos_simulados --limpar` também apaga esses alertas) |

Rodar o detector de novo **não duplica** alertas: cada janela tem um `id_janela` e janelas já registradas são
puladas.

## Comandos

Dentro de `projeto/`:

```bash
pip install -r requirements-ia.txt                       # scikit-learn + numpy (só onde a IA roda)
python manage.py gerar_eventos_simulados --qtd 50000     # dados de teste (camada Big Data)
python manage.py detectar_anomalias                      # detecta e grava os alertas
python manage.py detectar_anomalias --avaliar --nao-gravar   # mede acerto contra o gabarito, sem gravar
python manage.py detectar_anomalias --sem-simulados      # só eventos reais do sistema
python manage.py detectar_anomalias --json saida.json    # resultado completo em JSON
python manage.py detectar_anomalias --limpar             # apaga os alertas gerados pela IA
python manage.py test apps.test_anomalias                # testes
```

**Por que `requirements-ia.txt` separado:** scikit-learn, numpy e scipy somam ~150 MB, e o servidor web não
precisa deles, porque o painel só lê a tabela. Separar mantém o deploy (Vercel/Docker) leve. A IA roda como
tarefa agendada ou manual, de qualquer máquina com acesso ao banco.

## Como a avaliação foi feita

O gerador sintético da camada Big Data marca cada evento com `detalhes.cenario` (`normal` ou o nome da
anomalia injetada). Esse rótulo **nunca entra no modelo**; serve só para medir acerto depois.

1. **Calibração (semente 42):** escolha das features, da contaminação e do mínimo de eventos por janela.
2. **Validação (sementes 1 a 5):** dados novos, com os hiperparâmetros congelados. As métricas acima são a
   média dessas cinco rodadas.

Unidade de avaliação: a janela (entidade × 5 min). Uma janela conta como anômala se contém algum evento
injetado.

**Limitações, para constar no relatório:**

- O gerador usa a hora atual para posicionar os eventos, então a mesma semente não gera exatamente os mesmos
  dados em dias diferentes. Os números variam um pouco a cada execução, e por isso a avaliação usa 5 sementes.
- Os dados são sintéticos e os ataques injetados são justamente os que as regras conhecem. Isso favorece as
  regras por construção. Num sistema real, o valor do modelo está em pegar o que ninguém escreveu regra para
  cobrir, e o teste `test_pega_combinacao_que_nenhuma_regra_cobre` mostra isso: 8 falhas de login + 8 de
  decifragem + 8 acessos negados (tudo abaixo de 10) são pegos só pelo modelo.
- A contaminação fixa faz o modelo sempre apontar cerca de 3% das janelas ativas, mesmo num período sem ataque.
  Por isso o alerta só do modelo é `alerta`, e não `critico`.
- O detector processa o histórico inteiro a cada execução, o que leva ~3 s para 50 mil eventos. Com volume
  muito maior, o próximo passo seria processar só as janelas novas desde a última execução.
