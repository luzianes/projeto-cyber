# Big Data — tabela de eventos de segurança

## Visão geral

Esta camada corresponde à etapa **4. Big Data** da arquitetura do projeto: **coleta, armazenamento e
processamento dos eventos** gerados pelo sistema. Todo evento relevante para a segurança é gravado em
uma única tabela, `apps_eventoseguranca` (model `EventoSeguranca`, em `projeto/apps/models.py`).
A partir dela é possível medir o que acontece no sistema, comparar comportamento normal com
comportamento suspeito e alimentar a detecção de anomalias e o dashboard.

```
cifra · login · acesso · integridade · moderação · esteganografia · ataques
                          │  registrar_evento()
                          ▼
              tabela EventoSeguranca  ──►  analise_eventos.py  ──►  IA de anomalias / dashboard
                          ▲
        logs/security.log (importação do histórico)
```

O arquivo `logs/security.log` continua existindo como trilha em arquivo. A tabela é a versão
estruturada do mesmo registro, o que permite filtrar, agrupar, contar e exportar.

## O que é registrado

Cada linha da tabela é um evento. Os tipos existentes e o significado de cada um:

| Tipo | Quando é registrado | Metadados guardados em `detalhes` |
|---|---|---|
| `cifragem` | a cifra própria cifra uma mensagem | bytes de entrada, nº de blocos, nº de rodadas |
| `decifragem` | uma mensagem é decifrada com sucesso | nº de blocos |
| `falha_decifragem` | decifrar falha (chave errada, dado corrompido, padding inválido) | tipo do erro |
| `login_sucesso` | login válido | — |
| `login_falha` | login recusado | motivo: `senha_incorreta` ou `email_nao_cadastrado` |
| `login_bloqueado` | login barrado pelo CAPTCHA | motivo: `recaptcha_invalido` |
| `acesso_negado` | tentativa de acessar o que não é do usuário (ex.: não-empresário cadastrando cafeteria, acesso à reserva de outra pessoa) | motivo e id do objeto |
| `integridade_violada` | o SHA-256 de um arquivo enviado não confere com o registrado no upload | modelo, id e campo do arquivo |
| `moderacao_ia` | veredito da moderação automática de uma avaliação | `aprovado` ou `rejeitado` |
| `esteganografia` | texto cifrado escondido em uma imagem ou extraído dela | metadados da operação (ex.: bytes escondidos, PSNR) |
| `ataque_forca_bruta`, `ataque_diferencial`, `ataque_estatistico` | resumo de uma execução de cada ataque simulado | parâmetros e resultado do ataque |
| `anomalia` | comportamento anormal apontado pela IA | o que foi detectado e a pontuação |

### Colunas da tabela

| Coluna | Descrição |
|---|---|
| `criado_em` | data e hora do evento |
| `tipo` | um dos tipos acima |
| `categoria` | camada que gerou o evento: criptografia, autenticação, autorização, integridade, IA, esteganografia, ataque ou anomalia (derivada do tipo) |
| `severidade` | `info`, `alerta` ou `critico` |
| `sucesso` | `true` se a operação deu certo; `false` para falhas e negações |
| `usuario` | quem gerou o evento (texto, ver Decisões) |
| `ip` | endereço de origem, quando há requisição |
| `origem` | módulo ou fluxo que gerou o evento (ex.: `login_view`, `mensageria_cripto`) |
| `duracao_ms` | duração da operação em milissegundos, quando faz sentido |
| `detalhes` | metadados em JSON |
| `simulado` | `true` para eventos sintéticos gerados pelo script; `false` para eventos registrados pelo próprio sistema (inclui o histórico importado do log) |

Há índices em `criado_em`, `tipo`, `ip` e `usuario`, além de combinados (tipo + data, IP + data,
usuário + data), porque as consultas de análise quase sempre filtram por esses campos e por período.

## Privacidade

A tabela guarda **somente metadados**. Nunca entram texto de mensagens, chaves de criptografia,
texto cifrado nem senhas: `registrar_evento` descarta esses campos mesmo que sejam passados por engano.
O e-mail digitado em uma falha de login é gravado como pseudônimo (`usr_…`, o mesmo `pseudonimizar`
usado nos logs do projeto), e não em texto claro, para respeitar a LGPD.

## Registrando eventos

Qualquer parte do código registra um evento com `registrar_evento`:

```python
from apps.eventos import registrar_evento

registrar_evento('esteganografia', usuario='ana', origem='stego_lsb',
                 duracao_ms=12.3, detalhes={'bytes_escondidos': 96, 'psnr_db': 74.9})
```

Ela **nunca levanta exceção**: se a gravação falhar, o erro vai para o log de segurança e a operação
original (login, cifragem etc.) continua normalmente.

### Operações repetitivas, como a força bruta

Um ataque de força bruta chama `decifrar()` milhares de vezes com chaves erradas. Se cada tentativa
virasse uma linha, a tabela seria inundada de "falhas de decifragem" falsas, que não representam
comportamento real do sistema. Por isso existe o `silenciar_eventos()`, que suspende o registro dentro
do bloco. O padrão é executar a operação silenciada e registrar **um único evento-resumo** no final:

```python
from apps.eventos import registrar_evento, silenciar_eventos

with silenciar_eventos():
    resultado = rodar_forca_bruta(...)

registrar_evento('ataque_forca_bruta', origem='ataque_forca_bruta', duracao_ms=...,
                 sucesso=resultado.quebrou,
                 detalhes={'espaco_chaves': 2**16, 'tentativas': 65536})
```

## Análise dos dados

O módulo `apps/analise_eventos.py` lê a tabela e devolve estruturas prontas para uso:

| Função | O que devolve |
|---|---|
| `resumo_geral()` | totais, taxa de falha, contagem por tipo/categoria/severidade, IPs e usuários distintos, período coberto e duração média por tipo |
| `serie_temporal(tipo, 'hora'\|'dia')` | quantidade de eventos por hora ou dia, para gráficos de linha |
| `top_origens(tipo, 'ip'\|'usuario')` | ranking de quem mais gerou um tipo de evento (ex.: IPs com mais falhas de login) |
| `features_por_janela(minutos)` | uma linha por (IP, janela de tempo) com contagens por tipo, usuários distintos, taxa de falha de login e hora do dia |
| `exportar_csv()` | grava os resultados em CSV (abre direto no Excel) |

`features_por_janela` é a tabela de entrada da detecção de anomalias: uma janela com 150 falhas de login
em 5 minutos se destaca claramente das demais. A coluna `cenario_simulado` traz o gabarito dos dados
sintéticos (`normal` ou o nome da anomalia injetada) e serve apenas para **medir o acerto** da detecção;
ela não deve ser usada como variável de treino, senão o resultado fica artificialmente perfeito.

## Comandos

Rodar dentro da pasta `projeto/`:

```bash
python manage.py migrate                                  # cria a tabela (migration 0055)
python manage.py importar_logs_seguranca                  # importa o histórico de logs/security.log (idempotente)
python manage.py gerar_eventos_simulados --qtd 50000      # tráfego normal + anomalias injetadas (--seed para reproduzir)
python manage.py gerar_eventos_simulados --limpar         # apaga apenas os eventos simulados
python manage.py analisar_eventos                         # resumo no terminal
python manage.py analisar_eventos --csv eventos.csv --features-csv features.csv --janela 5
```

- **`importar_logs_seguranca`** traz para a tabela o que já havia sido registrado só em arquivo. Não duplica
  se for executado de novo e, por padrão, ignora linhas posteriores ao primeiro evento gravado direto pela
  aplicação (a partir daí o próprio sistema já grava na tabela).
- **`gerar_eventos_simulados`** cria um grande volume de eventos sintéticos: tráfego normal (com mais atividade
  em horário comercial) e anomalias injetadas, cada uma marcada com o cenário correspondente. Os cenários
  seguem os exemplos de anomalias do enunciado: `forca_bruta_login` (número incomum de tentativas de
  autenticação), `rajada_falha_decifragem` (frequência elevada de falhas de descriptografia),
  `varredura_acesso_negado` (padrão atípico de acesso), `geracao_incomum_de_eventos` (comportamento incomum na
  geração de eventos) e `integridade_violada` (alterações inesperadas em arquivos). Todos têm `simulado = true`.
- **`analisar_eventos`** imprime o resumo e, com as opções de CSV, exporta os eventos e as features por janela.

Os eventos também aparecem no Django Admin, em modo somente leitura, com filtros por tipo, severidade,
categoria, sucesso e simulado.

## Resultado de referência

Com 50 mil eventos simulados, a geração leva cerca de 9 segundos e a análise com exportação em CSV, cerca de
3 segundos. A saída completa dessa execução está em `evidencias/06-big-data-eventos/resultado_demo.txt`.
Esses números vêm de dados sintéticos e servem para mostrar que o processamento funciona em volume, e não
como medição de tráfego real.

## Decisões de projeto

* **Banco relacional com agregações SQL e leitura em streaming (`.iterator()`), em vez de Spark ou Hadoop.**
  O projeto já usa PostgreSQL e o volume testado (dezenas de milhares de eventos) é bem atendido por ele. Se o
  volume crescer muito, o mesmo modelo pode migrar para particionamento por data ou para um data warehouse.
* **`usuario` é texto, e não chave estrangeira.** Isso permite registrar tentativas com usuário inexistente
  e preserva o histórico mesmo se o usuário for excluído, o que é importante para auditoria.
* **O IP vem de `REMOTE_ADDR`**, igual ao que o login já fazia. O cabeçalho `X-Forwarded-For` pode ser
  forjado por quem faz a requisição, então só seria confiável atrás de um proxy controlado.
* **Os eventos não podem ser criados nem editados pelo admin.** Por serem trilha de auditoria, o admin serve para consulta.
