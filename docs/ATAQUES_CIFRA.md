# Ataques à cifra da mensageria

## Respostas

Os ataques foram rodados duas vezes: contra a cifra original (v1) e, depois das correções, contra a cifra
em uso (v2).

| Pergunta | v1 (original) | v2 (corrigida, em uso) |
|---|---|---|
| **Tem efeito avalanche?** | **Não.** Inverter 1 bit do texto muda **6,3%** dos bits do bloco e nunca mais de 1 byte dos 8. | **Sim.** Muda **50,0%** dos bits (ideal: 50%) e de 13 a 16 dos 16 bytes. |
| **Resiste à força bruta?** | **Não.** Com 24 bytes de texto conhecido, a chave de 64 bits sai em **~1 s**. | **Sim.** O ataque byte a byte não se aplica, e testar as 2^128 chaves levaria ~10^26 anos. |
| **Resiste à análise estatística?** | Sim (bytes cifrados uniformes). | Sim (bytes cifrados uniformes). |
| **Existem padrões na saída?** | **Na distribuição de bytes, não** (uniforme). **Na estrutura, sim:** cada byte cifrado dependia de 1 byte de entrada, 5 dos 8 bytes saíam na mesma posição, e o tamanho do texto vaza com margem de 8 bytes. | **Não.** Bytes uniformes, nenhum bloco repetido, cada byte depende do bloco inteiro. Só o tamanho do texto vaza (margem de 16 bytes). |
| **Dá para alterar a mensagem sem a chave?** | **Sim:** "2 pessoas" vira "9 pessoas". | **Não:** a alteração é detectada e a mensagem, rejeitada. |
| **Qual ataque foi mais eficaz?** | **Força bruta "dividir para conquistar"**: recuperou a chave em ~1 s. Ela só foi possível pelo que o **diferencial** revelou (bytes independentes). O estatístico não quebrou. | **Nenhum** quebrou a cifra. Só a força bruta com chave artificialmente reduzida a 16 bits teve sucesso, como demonstração do método. |
| **É segura?** | **Não.** | **Sim, contra os ataques realizados** (ver a ressalva abaixo). |

**Ressalva.** Resistir a estes ataques não prova que a v2 é segura. Uma cifra própria não passou pelos anos de
análise pública que o AES tem. Ela atende ao exercício, mas, para dado real, o recomendado continua sendo
AES-GCM ou Fernet.

- Cifra em uso: `projeto/apps/mensageria_cripto.py` (v2).
- Cifra original: `projeto/apps/cifra_v1_legada.py`, mantida só para migrar mensagens antigas e para reproduzir o "antes".
- Ataques: `projeto/apps/ataques_cripto.py`.
- Saídas completas: [`evidencias/05-ataques-cifra/antes/`](../evidencias/05-ataques-cifra/antes/resultado_ataques.txt)
  e [`evidencias/05-ataques-cifra/depois/`](../evidencias/05-ataques-cifra/depois/resultado_ataques.txt).

## Como rodar

Dentro da pasta `projeto/`:

```bash
python manage.py rodar_ataques                                   # cifra em uso (v2) + veredito (~5 s)
python manage.py rodar_ataques --cifra v1                        # cifra original, o "antes" (~4 s)
python manage.py rodar_ataques --ataque diferencial              # só um ataque (a opção pode repetir)
python manage.py rodar_ataques --bytes-desconhecidos 3           # força bruta real com 2^24 chaves (minutos)
python manage.py rodar_ataques --json resultados_ataques.json    # resultados completos para o dashboard
python manage.py rodar_ataques --nao-registrar                   # não grava eventos na tabela
python manage.py test apps.test_ataques apps.test_mensageria_cripto
```

## Modelo de ataque

O atacante conhece o algoritmo inteiro: S-box, P-box, número de rodadas e derivação das sub-chaves
(princípio de Kerckhoffs). Só a chave é segredo. Os ataques chamam as funções reais `cifrar()` e
`decifrar()` sempre que possível. Quando o teste precisa de IV fixo, usam `cifrar_com_iv()`, e um teste
confere que ela produz os mesmos bytes que `cifrar()` nas duas versões.

## 1. Ataque diferencial: há efeito avalanche?

**Método.** Mantém tudo fixo, inverte 1 bit da entrada e conta quantos bits da saída mudaram. Foram 200
blocos sorteados × todos os bits do texto, 200 × todos os bits da chave, e mensagens de 5 blocos para
observar o encadeamento.

| Medição | v1 | v2 | Ideal |
|---|---|---|---|
| 1 bit do texto (mesma chave e IV) | 6,3% dos bits; **1 byte** de 8 | **50,0%**; 13 a 16 bytes de 16 | ~50%, bloco inteiro |
| 1 bit da chave (mesmo texto) | 22,8%; até 4 bytes | **50,0%**; 16 bytes | ~50% |
| Mensagem de 5 blocos, 1 bit no 1º bloco | 6,2% da mensagem | 50,3% | ~50% |
| Alterar 1 byte do IV ("2" → "9") | aceita: `Para 9 pessoas` | **rejeitada** | rejeitada |

**Por que a v1 não tinha avalanche.** Nenhuma etapa da rodada misturava bytes entre si. O XOR e a S-box agem
byte a byte, e a P-box só **troca bytes de lugar**. Assim, cada byte cifrado dependia de **um único byte** da
entrada e de um byte da chave por rodada. A cifra se comportava como 8 cifras independentes de 1 byte, e 5
dos 8 bytes saíam na mesma posição em que entraram:

| Byte cifrado (v1) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| vem do byte de entrada | 3 | 0 | 2 | 1 | 4 | 5 | 6 | 7 |
| bytes da chave usados (rodadas 1 a 4) | 3,1,3,6 | 0,2,5,3 | 2,6,1,7 | 1,4,2,4 | 4,3,7,2 | 5,0,6,5 | 6,7,0,1 | 7,5,4,0 |

**Por que a v2 tem.** Cada rodada ganhou uma mistura de colunas (MixColumns, multiplicação de matriz em
GF(2^8), a mesma do AES). Ela faz cada byte de uma coluna de 4 bytes depender dos 4. A P-box virou o
ShiftRows do AES, que espalha os bytes de cada coluna por colunas diferentes. Com as duas juntas, um único
byte de entrada já afeta o bloco inteiro depois de duas rodadas, e a v2 tem 10.

**Cuidado com o teste ingênuo.** Cifrar duas vezes com `cifrar()` um texto que difere em 1 bit dá **~50% de
diferença nas duas versões**, inclusive na v1, que não tem avalanche. Cada chamada sorteia um IV novo, então
a diferença vem do IV e não da cifra. Por isso o teste mantém o IV fixo.

**S-box.** Ficou a mesma (uniformidade diferencial 14; a do AES é 4). Ela não era o problema: com a mistura
entre bytes e 10 rodadas, todo diferencial precisa atravessar dezenas de S-boxes.

## 2. Ataque de força bruta

**(a) Força bruta real com chave reduzida.** A chave é reduzida artificialmente a 2 bytes secretos (65.536
possibilidades). O atacante tem só o texto cifrado e testa todas as chaves com o `decifrar()` real. Nas duas
versões a chave foi achada em 11.481 tentativas (v1: ~1 s; v2: ~0,2 s, porque a autenticação descarta a
chave errada antes de decifrar). Isso é esperado: o teste mostra que o **método** funciona. O que protege é
o tamanho da chave verdadeira.

**(b) Estimativa para a chave real.**

| | v1 | v2 |
|---|---|---|
| Espaço de chaves | 2^64 ≈ 1,8 × 10^19 | 2^128 ≈ 3,4 × 10^38 |
| Taxa medida (`decifrar()` em Python, 1 núcleo) | ~10.600 chaves/s | ~62.000 chaves/s |
| Tempo médio | ~27,6 milhões de anos | **~8,7 × 10^25 anos** |

O tempo da v1 só protegia contra quem roda Python num notebook. Chaves de 56 e 64 bits já foram quebradas na
prática: o DES (56 bits) em 56 horas por uma máquina dedicada da EFF, em 1998, e o desafio RC5 de 64 bits pela
distributed.net, em 2002. O mínimo recomendado hoje é 128 bits, e o NIST não aceita menos de 112.

**(c) "Dividir para conquistar": a falha que quebrava a v1 em ~1 s.** Como cada byte cifrado da v1 dependia de
só 4 bytes da chave, dava para atacar as 8 posições do bloco separadamente. Em cada posição, um ataque de
encontro no meio testa 2^16 combinações pela frente e 2^8 por trás, ~3 milhões de consultas à S-box no total.
Conhecendo só os 24 primeiros bytes de uma mensagem (`"Olá, equipe da cafeteri"`), o ataque recuperou a chave
dinâmica de 64 bits em ~1 s e decifrou a mensagem inteira. Com 16 bytes conhecidos, levou ~14 s.

Na v2 o ataque **não se aplica**. Antes de rodar, ele mede de quais bytes de entrada cada byte cifrado
depende, e na v2 cada byte de entrada afeta todos os 16 bytes do bloco. Não há partes independentes para
atacar separadamente, e a derivação das sub-chaves por HMAC também deixou de ser uma rotação da chave.

## 3. Ataque estatístico (análise de frequência)

**Método.** 2.000 mensagens fictícias no estilo cliente → cafeteria, cada uma com chave nova (como no sistema).
O ataque compara a distribuição de bytes do texto claro com a do texto cifrado (sem o IV e sem a tag, que são
aleatórios por construção) usando entropia e teste qui-quadrado contra a distribuição uniforme.

| | Texto claro | Cifrado v1 | Cifrado v2 |
|---|---|---|---|
| Bytes analisados | 130.747 | 139.640 | 148.432 |
| Entropia (máx. 8 bits/byte) | 4,58 | 7,999 | 7,999 |
| Qui-quadrado (p-valor) | 1.960.358 (p ≈ 0) | 247,6 (p = 0,62) | 249,2 (p = 0,59) |
| Mais frequentes | `' '` 15%, `a` 9,9%, `o` 8,5% | ≤ 0,44% (uniforme: 0,39%) | ≤ 0,44% |

**Resultado: a análise de frequência não quebra nenhuma das duas.** Isso vem do modo de operação, não das
rodadas: 8 blocos de texto idênticos viram 8 blocos cifrados diferentes com CBC, mas 1 bloco repetido 8
vezes sem o encadeamento. A mesma mensagem cifrada duas vezes com a mesma chave também sai diferente, por
causa do IV aleatório.

**Vazamento que sobra: o tamanho.** O tamanho do texto é deduzido do cifrado com margem de 1 bloco (8 bytes na
v1, 16 na v2). Isso é esperado em cifras de bloco e só importa quando o tamanho já revela o conteúdo, por
exemplo "sim" e "não". Não foi corrigido.

## Correções aplicadas

| Problema encontrado | Correção | Onde |
|---|---|---|
| P-box só trocava bytes de lugar: sem avalanche, cifra quebrável byte a byte | Mistura de colunas (MixColumns) em toda rodada + P-box no formato ShiftRows | `mensageria_cripto.py` |
| Chave de 64 bits | 128 bits (bloco também de 16 bytes) | `mensageria_cripto.py` |
| Sub-chaves eram rotações da chave | Derivadas por HMAC-SHA256, uma por rodada | `mensageria_cripto.py` |
| 4 rodadas terminando numa S-box pública | 10 rodadas + XOR final com uma 11ª sub-chave | `mensageria_cripto.py` |
| Sem autenticação: dava para trocar "2 pessoas" por "9 pessoas" | HMAC-SHA256 sobre IV + blocos, conferido **antes** de decifrar | `mensageria_cripto.py` |
| A chave de cada mensagem ficava em claro ao lado do texto cifrado | `MensagemPrivada.chave` virou `EncryptedCharField` (Fernet com a `FIELD_ENCRYPTION_KEY`, que fica fora do banco) | `models.py`, migration 0056 |
| A chave aparecia no admin | Campo removido do admin | `admin.py` |
| Mensagens antigas cifradas com a v1 | A migration 0056 decifra cada uma e a recifra com a v2 e uma chave nova. Ela é reversível. | `migrations/0056_…` |
| Força bruta sujaria o log com falsas falhas de decifragem | Ataques rodam em `modo_ataque()`: registro suspenso e 1 evento-resumo por ataque | `ataques_cripto.py` |

**Compatibilidade.** A interface não mudou: `gerar_chave()`, `cifrar(texto, chave)` e `decifrar(cifrado, chave)`.
Mudou o formato. A chave agora tem 16 bytes (24 caracteres em base64), e o texto cifrado é
`base64(IV + blocos + tag)`. A esteganografia (Pessoa 3) passou a calcular a capacidade da imagem com
`tamanho_cifrado()` da própria cifra. Chaves e imagens geradas com a v1 não são mais aceitas.

**Para aplicar no banco:** `python manage.py migrate`. Com mensagens já gravadas, a `FIELD_ENCRYPTION_KEY`
precisa estar configurada.

## Eventos registrados (Big Data)

Com a cifra em uso, cada execução grava **um evento-resumo por ataque** na tabela `EventoSeguranca`, conforme o
padrão descrito em `docs/BIG_DATA_EVENTOS.md`. As tentativas individuais nunca viram eventos. Execuções com
`--cifra v1` não gravam nada, porque o painel mostra o último resultado como o veredito atual da cifra.

| Campo | Valor |
|---|---|
| `tipo` | `ataque_diferencial`, `ataque_forca_bruta` ou `ataque_estatistico` (categoria `ataque`) |
| `origem` | `ataques_cripto` |
| `sucesso` | `true` quando o ataque encontrou vulnerabilidade |
| `duracao_ms` | duração total do ataque |
| `detalhes` | métricas resumidas, como `cifra`, `percentual_bits_texto`, `tem_avalanche`, `maleavel`, `taxa_chaves_por_s`, `anos_estimados_caso_medio`, `dividir_conquistar_aplicavel`, `dividir_conquistar_quebrou`, `entropia_cifrado`, `p_valor_cifrado` e `uniforme`, além dos parâmetros usados |

Os eventos guardam só métricas: nenhuma chave, texto claro ou texto cifrado entra na tabela, e há teste
automatizado para isso. Para o dashboard, `--json` exporta os detalhes completos; há exemplos em
`evidencias/05-ataques-cifra/antes/` e `depois/`.
