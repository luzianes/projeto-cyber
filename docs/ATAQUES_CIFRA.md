# Ataques à cifra da mensageria

## Respostas

| Pergunta | Resposta | Evidência principal |
|---|---|---|
| **A cifra tem efeito avalanche?** | **Não.** | Inverter 1 bit do texto muda **6,3%** dos bits do bloco cifrado (o ideal é ~50%) e **nunca mais de 1 byte** dos 8. Inverter 1 bit da chave muda 22,8%. |
| **A cifra é segura?** | **Não.** | Com 24 bytes de texto conhecido (uma saudação padrão, por exemplo), a **chave inteira de 64 bits é recuperada em ~1 s** e o restante da mensagem é decifrado. A cifra também é maleável: dá para trocar "2 pessoas" por "9 pessoas" sem conhecer a chave. |

O que funciona: a **análise de frequência não quebra a cifra**. Os bytes cifrados são estatisticamente
uniformes graças ao encadeamento CBC com IV aleatório e à chave nova por mensagem.

Alvo: `projeto/apps/mensageria_cripto.py` (cifra própria da Pessoa 1: chave dinâmica de 8 bytes, blocos de
8 bytes, 4 rodadas de XOR + S-box + permutação, encadeamento CBC). Código dos ataques:
`projeto/apps/ataques_cripto.py`. Saída completa da execução:
[`evidencias/05-ataques-cifra/resultado_ataques.txt`](../evidencias/05-ataques-cifra/resultado_ataques.txt).

## Como rodar

Dentro da pasta `projeto/`:

```bash
python manage.py rodar_ataques                                   # os três ataques + veredito (~4 s)
python manage.py rodar_ataques --ataque diferencial              # só um ataque (a opção pode repetir)
python manage.py rodar_ataques --bytes-desconhecidos 3           # força bruta real com 2^24 chaves (~25 min)
python manage.py rodar_ataques --blocos-conhecidos 2             # recuperar a chave com só 16 bytes conhecidos (~15 s)
python manage.py rodar_ataques --json resultados_ataques.json    # resultados completos para o dashboard
python manage.py rodar_ataques --nao-registrar                   # não grava eventos na tabela
python manage.py test apps.test_ataques                          # testes automatizados
```

## Modelo de ataque

O atacante conhece o algoritmo inteiro: S-box, P-box, número de rodadas e derivação das sub-chaves
(princípio de Kerckhoffs). Só a chave é segredo. Os ataques chamam as funções reais `cifrar()` e
`decifrar()` sempre que possível. Quando o teste precisa de IV fixo, usam `cifrar_com_iv()`, e um teste
confere que ela produz exatamente os mesmos bytes que `cifrar()`.

## 1. Ataque diferencial: há efeito avalanche?

**Método.** Mantém tudo fixo, inverte 1 bit da entrada e conta quantos bits da saída mudaram. Foram 200
blocos sorteados × 64 bits do texto, 200 × 64 bits da chave, e mensagens de 5 blocos para observar o
encadeamento.

| Medição | Resultado | Cifra com avalanche |
|---|---|---|
| 1 bit do texto (mesma chave e IV) | 4,03 de 64 bits (**6,3%**), no máximo **1 byte** alterado | ~32 bits (50%), todos os bytes afetados |
| 1 bit da chave (mesmo texto) | 14,58 de 64 bits (22,8%), no máximo 4 bytes | ~50% |
| Mensagem de 5 blocos, 1 bit no 1º bloco | 6,2% da mensagem; 1 byte em cada bloco seguinte | ~50% |
| 1 bit no último bloco | os blocos anteriores ficam **idênticos** | — (é próprio do CBC) |
| S-box: uniformidade diferencial | 14 (um diferencial passa com probabilidade de 5,5%) | AES: 4 |

**Por que não há avalanche.** Nenhuma etapa da rodada mistura bytes entre si. O XOR e a S-box agem byte a byte,
e a P-box só **troca bytes de lugar**. Assim, cada byte do bloco cifrado depende de **um único byte** da entrada
e de um byte da chave por rodada:

| Byte cifrado | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| vem do byte de entrada | 3 | 0 | 2 | 1 | 4 | 5 | 6 | 7 |
| bytes da chave usados (rodadas 1 a 4) | 3,1,3,6 | 0,2,5,3 | 2,6,1,7 | 1,4,2,4 | 4,3,7,2 | 5,0,6,5 | 6,7,0,1 | 7,5,4,0 |

Depois das 4 rodadas, a permutação devolve 5 dos 8 bytes (2, 4, 5, 6 e 7) à mesma posição em que entraram. Na
prática, a cifra funciona como **8 cifras independentes de 1 byte**. O CBC espalha a mudança para os blocos
seguintes, mas só 1 byte por bloco e só para a frente.

**Cuidado com o teste ingênuo.** Cifrar duas vezes com `cifrar()` um texto que difere em 1 bit dá **~50% de
diferença**, o que parece avalanche. Esse resultado é falso: cada chamada sorteia um IV novo, então a diferença
vem do IV e não da cifra. Por isso o teste mantém o IV fixo.

**Maleabilidade.** Como não há autenticação (MAC), quem tem acesso ao texto cifrado pode alterá-lo de forma
previsível. Fazendo XOR de `'2' ^ '9'` no byte do IV que corresponde ao "2", a mensagem decifra sem erro como
`'Para 9 pessoas, sábado às 20h.'`, sem que o atacante conheça a chave.

## 2. Ataque de força bruta

**(a) Força bruta real com chave reduzida.** Como sugerido na própria cifra, a chave foi reduzida
artificialmente a 2 bytes secretos (65.536 possibilidades). O atacante tem só o texto cifrado e testa todas as
chaves com o `decifrar()` real. A chave certa é a primeira que produz padding válido e texto legível. Resultado:
achada em 11.481 tentativas (1,1 s) e mensagem recuperada.

**(b) Estimativa para a chave real de 64 bits.**

| | |
|---|---|
| Espaço de chaves | 2^64 = 18.446.744.073.709.551.616 |
| Taxa medida | ~10.600 chaves/s (`decifrar()` em Python, 1 núcleo) |
| Tempo médio (metade do espaço) | **~27,6 milhões de anos** |

Esse número protege contra quem roda Python num notebook, mas não contra um atacante com recursos. Chaves desse
tamanho já foram quebradas na prática: uma chave DES de 56 bits foi achada em 56 horas por uma máquina dedicada
(EFF, 1998), e o desafio RC5 de 64 bits foi resolvido por computação distribuída (distributed.net, 2002). A
recomendação atual é usar no mínimo 128 bits (AES-128); o NIST não aceita menos de 112.

**(c) Força bruta "dividir para conquistar": a chave completa em ~1 s.** Como cada byte cifrado depende de
apenas 4 bytes da chave (tabela acima), não é preciso testar as 2^64 chaves de uma vez. Basta atacar cada uma
das 8 posições separadamente. Em cada posição, um ataque de encontro no meio testa 2^16 combinações pela frente
e 2^8 por trás, em vez de 2^32. As 8 respostas compartilham bytes da chave, e a interseção deixa uma única chave.

- Requisito: texto conhecido. Com **24 bytes** (3 blocos), a chave é única. Com 16 bytes também funciona (~15 s).
- Cenário realista: mensagens que começam com uma saudação previsível. No teste, conhecendo só
  `"Olá, equipe da cafeteri"`, o ataque recuperou a chave dinâmica real de 64 bits e decifrou a mensagem
  inteira, incluindo o voucher fictício no final.
- Custo: ~3 milhões de consultas à S-box, contra 2^64 decifragens.

A chave dinâmica (uma por mensagem) limita o estrago a uma mensagem por ataque, mas não impede o ataque.

## 3. Ataque estatístico (análise de frequência)

**Método.** 2.000 mensagens fictícias no estilo cliente → cafeteria, cada uma com chave nova (como no sistema).
O ataque compara a distribuição de bytes do texto claro com a do texto cifrado (sem o IV, que é aleatório por
construção) usando entropia e teste qui-quadrado contra a distribuição uniforme (255 graus de liberdade).

| | Texto claro | Texto cifrado |
|---|---|---|
| Bytes analisados | 130.747 | 139.640 |
| Valores distintos | 55 | 256 |
| Entropia (máx. 8 bits/byte) | 4,58 | **7,999** |
| Qui-quadrado (p-valor) | 1.960.358 (p ≈ 0) | **247,6 (p = 0,62)** |
| Mais frequentes | `' '` 15%, `a` 9,9%, `o` 8,5% | nenhum acima de 0,44% (uniforme: 0,39%) |

**Resultado: a análise de frequência não quebra a cifra.** O texto cifrado é indistinguível de bytes
aleatórios por esse critério. Isso vem do modo de operação, não das rodadas:

- **8 blocos de texto idênticos** viram 8 blocos cifrados diferentes com CBC. Sem o encadeamento (cada bloco
  cifrado sozinho), viram **1 bloco repetido 8 vezes** e o padrão do texto ficaria visível.
- A mesma mensagem cifrada duas vezes com a mesma chave sai completamente diferente, por causa do IV aleatório.

**Vazamento que sobra: o tamanho.** `len(cifrado) = 8 × (len(texto) // 8 + 1)`. Nas 2.000 mensagens, o
tamanho do texto foi deduzido do cifrado com margem de 8 bytes. Isso é esperado em cifras de bloco e só
importa quando o tamanho já revela o conteúdo, por exemplo "sim" e "não".

## Outros problemas encontrados

- **A chave fica gravada ao lado do texto cifrado.** `MensagemPrivada.chave` é um campo em texto claro na mesma
  linha que `texto_cifrado`. Quem lê o banco (backup vazado, injeção de SQL, acesso ao admin) decifra todas as
  mensagens sem atacar a cifra. Esse é o risco mais grave na prática.
- **Força bruta suja o log.** Cada `decifrar()` com chave errada grava `falha_decriptografia` em
  `logs/security.log`, e o `importar_logs_seguranca` converte essas linhas em eventos de falha de decifragem.
  Uma força bruta de 65 mil tentativas viraria 65 mil eventos falsos para a IA de anomalias. Por isso os ataques
  rodam em `modo_ataque()`, que suspende o registro de eventos e filtra essas linhas do log.

## Recomendações

1. **Em produção, usar cifra autenticada pronta:** AES-GCM ou Fernet (a biblioteca `cryptography` já está no
   projeto e a Fernet já protege as reservas). Cifra própria não deve proteger dado real.
2. **Para a cifra do exercício ficar mais forte:** incluir uma etapa que misture os bytes do bloco a cada rodada
   (como o MixColumns do AES), aumentar a chave para 128 bits, derivar as sub-chaves de forma não linear e
   autenticar IV + texto cifrado com HMAC (encrypt-then-MAC). Depois disso, rodar `rodar_ataques` de novo:
   avalanche ~50% e o item (c) deixando de recuperar a chave são o critério de aceite.
3. **Não guardar a chave da mensagem em claro:** cifrá-la com uma chave-mestra vinda de variável de ambiente
   (por exemplo, a `FIELD_ENCRYPTION_KEY` que o projeto já usa).

## Eventos registrados (Big Data)

Cada execução grava **um evento-resumo por ataque** na tabela `EventoSeguranca`, conforme o padrão descrito em
`docs/BIG_DATA_EVENTOS.md`. As tentativas individuais nunca viram eventos.

| Campo | Valor |
|---|---|
| `tipo` | `ataque_diferencial`, `ataque_forca_bruta` ou `ataque_estatistico` (categoria `ataque`) |
| `origem` | `ataques_cripto` |
| `sucesso` | `true` quando o ataque encontrou vulnerabilidade |
| `duracao_ms` | duração total do ataque |
| `detalhes` | métricas resumidas, por exemplo `percentual_bits_texto`, `tem_avalanche`, `maleavel`, `taxa_chaves_por_s`, `anos_estimados_caso_medio`, `dividir_conquistar_quebrou`, `entropia_cifrado`, `p_valor_cifrado`, `uniforme`, e os parâmetros usados |

Os eventos guardam só métricas: nenhuma chave, texto claro ou texto cifrado entra na tabela, e há teste
automatizado para isso. Para o dashboard, `--json` exporta também os detalhes completos, como o mapa de bytes,
os bytes mais frequentes e os candidatos por posição. Um exemplo está em
[`evidencias/05-ataques-cifra/resultados_ataques.json`](../evidencias/05-ataques-cifra/resultados_ataques.json).
No banco local, rode `python manage.py migrate` antes, para criar a tabela de eventos.
