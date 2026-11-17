# Relatório final — Projeto 2: criptografia, ataques, Big Data e IA

> **Rascunho consolidado.** Junta o que cada parte entregou no repositório, com os números das evidências.
> Revisar antes de enviar.

## Arquitetura

```
1. Entrada        mensagem privada cliente → cafeteria
2. Criptografia   cifra própria (SPN + CBC, chave dinâmica)          — Pessoa 1
   ├─ Ataques     força bruta, diferencial, estatístico              — Pessoa 2
3. Esteganografia texto cifrado escondido em imagem (LSB)            — Pessoa 3
4. Big Data       tabela EventoSeguranca: todo evento de segurança   — Pessoa 4
5. IA             detecção de anomalias (regras + Isolation Forest)  — Pessoa 5
6. Dashboard      /painel-seguranca/ + este relatório                — Pessoa 6
```

Todas as camadas conversam pela tabela de eventos. A cifra registra cifragens e falhas de decifragem; o login,
o controle de acesso e a verificação de integridade registram tentativas e negações; os ataques registram um
resumo por execução; a IA lê tudo isso e grava os alertas; e o painel mostra o resultado.

| Parte | Responsável | Documento | Evidência |
|---|---|---|---|
| 1. Cifra | Luziane | `projeto/apps/mensageria_cripto.py` (docstring) | testes em `apps/test_mensageria_cripto.py` e `apps/test_eventos.py` |
| 2. Ataques | Maju | [ATAQUES_CIFRA.md](ATAQUES_CIFRA.md) | [`evidencias/05-ataques-cifra/`](../evidencias/05-ataques-cifra/) |
| 3. Esteganografia | Davi | `projeto/apps/esteganografia.py` (docstring) e a seção 3 abaixo | [`evidencias/09-esteganografia/`](../evidencias/09-esteganografia/) |
| 4. Big Data | Lisa | [BIG_DATA_EVENTOS.md](BIG_DATA_EVENTOS.md) | [`evidencias/06-big-data-eventos/`](../evidencias/06-big-data-eventos/) |
| 5. IA de anomalias | Paulo | [IA_ANOMALIAS.md](IA_ANOMALIAS.md) | [`evidencias/07-ia-anomalias/`](../evidencias/07-ia-anomalias/) |
| 6. Dashboard | Paulo | [PAINEL_SEGURANCA.md](PAINEL_SEGURANCA.md) | [`evidencias/08-painel-seguranca/`](../evidencias/08-painel-seguranca/) |

---

## 1. Criptografia: cifra própria da mensageria

**Algoritmo (versão 2, corrigida após os ataques da seção 2).** Rede de substituição-permutação (SPN) em
blocos de 16 bytes, inspirada na estrutura do AES, de forma simplificada:

- **Chave dinâmica:** `gerar_chave()` sorteia 16 bytes (128 bits) novos para cada mensagem. Nenhuma chave é fixa.
- **Sub-chaves:** 11, derivadas da chave por HMAC-SHA256 (uma por rodada, mais uma final).
- **Rodadas (10):** XOR com a sub-chave da rodada → substituição byte a byte por uma S-box fixa (confusão) →
  permutação da ordem dos bytes no bloco (ShiftRows) → mistura de colunas (MixColumns), que faz cada byte
  depender dos outros (difusão). Ao final, um XOR com a 11ª sub-chave.
- **Modo de operação:** encadeamento CBC com IV aleatório de 16 bytes.
- **Autenticação:** HMAC-SHA256 sobre IV + blocos, conferido antes de decifrar. Chave errada ou texto alterado
  são rejeitados sem decifrar nada.
- **Formato:** padding PKCS7; a saída é IV + blocos + tag, em base64.

A versão 1 (blocos e chave de 8 bytes, 4 rodadas, sem mistura de bytes e sem autenticação) foi quebrada nos
ataques e ficou em `cifra_v1_legada.py`, só para migrar as mensagens antigas e reproduzir os ataques.

**Funcionamento no sistema.** O cliente envia uma mensagem privada à cafeteria. O texto é cifrado com uma chave
nova e gravado em `MensagemPrivada`. A chave da mensagem é guardada **cifrada** (Fernet com a
`FIELD_ENCRYPTION_KEY`, que fica fora do banco), e o dono da cafeteria lê a mensagem decifrada na caixa de
entrada. Cada cifragem e cada decifragem vira um evento, sem texto nem chave. Uma decifragem que falha (chave
errada, mensagem alterada) vira um evento `falha_decifragem`.

**Testes.** Ida e volta, chave errada e qualquer byte alterado sempre rejeitados, vetor de teste do
MixColumns, migração das mensagens da v1 (`apps/test_mensageria_cripto.py`) e ausência de texto ou chave nos
eventos (`apps/test_eventos.py`).

## 2. Ataques à cifra

Os ataques foram rodados contra a cifra original (v1), que foi quebrada, e de novo contra a versão corrigida
(v2), que está em uso.

| Pergunta | v1 (original) | v2 (corrigida, em uso) |
|---|---|---|
| Tem efeito avalanche? | **Não.** Inverter 1 bit do texto muda **6,3%** dos bits do bloco e nunca mais de 1 byte em 8. A P-box só trocava bytes de lugar: 8 cifras independentes de 1 byte. | **Sim.** Muda **50,0%** dos bits (ideal: 50%), alterando de 13 a 16 dos 16 bytes. |
| Resiste à força bruta? | **Não.** Testar as 2^64 chaves levaria ~27,6 milhões de anos em Python, mas o ataque **dividir para conquistar** recupera a chave em **~1 s** com 24 bytes de texto conhecido. | **Sim.** O ataque byte a byte não se aplica (cada byte cifrado depende de todos os 16), e testar as 2^128 chaves levaria ~8,7 × 10^25 anos. |
| Resiste à análise estatística? | **Sim.** Entropia de 7,999 bits/byte, qui-quadrado com p = 0,62. | **Sim.** Entropia de 7,999 bits/byte, p = 0,59. |
| Existem padrões na saída? | **Na distribuição de bytes, não** (uniforme). **Na estrutura, sim:** cada byte cifrado dependia de 1 byte de entrada, 5 dos 8 bytes saíam na mesma posição, e o tamanho do texto vaza com margem de 8 bytes. | **Não.** Bytes uniformes, nenhum bloco repetido, cada byte depende do bloco inteiro. Só o tamanho do texto vaza (margem de 16 bytes). |
| Dá para alterar a mensagem sem a chave? | **Sim:** "2 pessoas" vira "9 pessoas". | **Não:** a autenticação rejeita a mensagem. |
| Qual ataque foi mais eficaz? | **Força bruta "dividir para conquistar"**: recuperou a chave em ~1 s. Ela só foi possível pelo que o **diferencial** revelou (bytes independentes). O estatístico não quebrou. | **Nenhum** quebrou a cifra. Só a força bruta com chave artificialmente reduzida a 16 bits teve sucesso, como demonstração do método. |
| É segura? | **Não.** | **Sim, contra os ataques realizados.** Por ser uma cifra própria, sem análise pública, a recomendação para dado real continua sendo AES-GCM ou Fernet. |

Problema mais grave na prática, também corrigido: **a chave de cada mensagem ficava gravada em claro na mesma
linha do texto cifrado**, e quem lia o banco decifrava tudo sem atacar a cifra. Agora ela é guardada cifrada,
e a migration 0056 recifrou as mensagens antigas com a v2.

Detalhes, método e recomendações: [ATAQUES_CIFRA.md](ATAQUES_CIFRA.md).

## 3. Esteganografia (LSB)

**Algoritmo.** Substituição do bit menos significativo (LSB). O texto cifrado pela mensageria é gravado bit a bit
no último bit de cada canal R, G e B dos pixels, linha a linha, a partir do canto superior esquerdo. Cada amostra
de cor muda no máximo 1 unidade (numa escala de 0 a 255), o que não é visível. O canal alfa (transparência) nunca
recebe dados. Antes da mensagem vai um cabeçalho de 44 bytes: identificador e versão do formato (8 bytes), tamanho
dos dados (4 bytes) e um SHA-256 do cabeçalho e dos dados (32 bytes), que detecta corrupção. A capacidade é de 3
bits por pixel, ou seja, largura × altura × 3 / 8 bytes, menos o cabeçalho. A saída é sempre PNG, um formato sem
perdas.

**Funcionamento no sistema.** A ferramenta fica em `/esteganografia/` e exige login.

- **Esconder:** o usuário envia uma imagem (PNG, JPEG, BMP ou WebP) e a mensagem. A mensagem é cifrada com a cifra
  da mensageria (v2), com uma chave nova ou uma informada pelo usuário. O texto cifrado vai num envelope com
  HMAC-SHA256 e é gravado nos LSBs. O usuário baixa o PNG e a chave, que deve guardar separada da imagem.
- **Extrair:** o usuário envia o PNG. Sem a chave, recebe só o texto cifrado. Com a chave, o envelope é autenticado
  e a mensagem é decifrada.

Nenhuma mensagem, chave ou imagem fica guardada no servidor. Cada operação vira um evento `esteganografia` só com
métricas (capacidade, PSNR, duração e resultado), e uma chave errada vira `falha_decifragem`, que alimenta a IA de
anomalias. O upload é validado pelo conteúdo, não pela extensão: limite de 16 MiB e de 8 milhões de pixels, e
recusa de imagens animadas, de alta profundidade de cor e de "bombas de descompressão".

**Testes.** 61 testes automatizados (`apps/test_esteganografia.py` e `apps/test_esteganografia_integracao.py`):

- ida e volta com textos UTF-8;
- capacidade exata aceita e 1 byte a mais recusado;
- checksum que detecta 1 bit alterado;
- preservação do canal alfa e dos metadados de cor;
- limites de upload e de pixels, e arquivos inválidos ou truncados;
- fluxo completo com a cifra, nas rotas HTTP autenticadas, sem segredos nos eventos.

**Resultados.** Medidos com `python manage.py demonstrar_esteganografia` numa foto de 3024 × 920 px
(`img-home-cliente.png`), com capacidade de 1.043.236 bytes:

| Mensagem | Texto | Gravado na imagem | Capacidade usada | PSNR |
|---|---|---|---|---|
| Curta (pedido de reserva) | 97 bytes | 301 bytes | 0,03% | 86,1 dB |
| Longa (perto do limite de 64 KiB do serviço) | 63.583 bytes | 84.929 bytes | 8,1% | 62,0 dB |
| Capacidade inteira (pior caso, só a camada LSB) | 1.043.236 bytes | 1.043.236 bytes | 100% | 51,1 dB |

O PSNR mede a diferença entre a imagem original e a modificada: acima de ~40 dB, a alteração é considerada
imperceptível. Mesmo com a imagem inteira ocupada, o PSNR fica em 51,1 dB. A mensagem ocupa mais espaço do que o
texto original porque soma o IV e a tag da cifra, a codificação em base64 e o envelope autenticado: cerca de 3 vezes
o texto numa mensagem curta e 1,34 vez numa longa.

| Extração da mensagem curta | Resultado |
|---|---|
| Com a chave certa | Mensagem recuperada, idêntica |
| Sem chave | Só o texto cifrado, sem decifrar |
| Com outra chave | Recusada (autenticação inválida) |
| 1 bit alterado na imagem | Recusada (integridade inválida) |
| Recomprimida em JPEG (qualidade 95) | Recusada (dados perdidos) |
| Redimensionada em 1 pixel | Recusada (integridade inválida) |

![Original, imagem com a mensagem longa e diferença ampliada](../evidencias/09-esteganografia/comparacao.jpg)

Na figura, de cima para baixo: a imagem original, a imagem com a mensagem longa (iguais a olho nu) e a diferença
entre elas, ampliada para ficar visível. A faixa no topo são os pixels que guardam a mensagem.

**Limitações.**

- **Fragilidade.** O LSB não sobrevive a compressão com perdas, redimensionamento ou edição. A imagem precisa
  circular como o PNG gerado. Quando isso não acontece, a extração falha de forma detectada e nunca devolve uma
  mensagem errada.
- **Detectabilidade.** Os bits ficam em sequência a partir do topo da imagem. Técnicas de esteganálise, como o teste
  qui-quadrado dos LSBs, podem indicar que há algo escondido, embora não revelem o conteúdo, que está cifrado.
  Espalhar os bits em posições sorteadas a partir da chave dificultaria essa detecção.
- **Autenticação dupla.** O envelope com HMAC foi criado quando a cifra (v1) ainda não tinha autenticação. Com a
  v2, que já autentica, ele ficou redundante; hoje serve para conferir a chave antes de decifrar.

## 4. Big Data: tabela de eventos de segurança

**O que é.** Uma tabela única, `EventoSeguranca`, com uma linha por evento: data, tipo, categoria, severidade,
sucesso, usuário, IP, origem, duração e metadados em JSON. Tem índices por data, tipo, IP e usuário. Guarda **só
metadados**: texto de mensagem, chave e senha são descartados mesmo se passados por engano, e o e-mail digitado
numa falha de login é pseudonimizado (LGPD).

**Fontes.** Cifra, login (sucesso, falha, bloqueio por CAPTCHA), acesso negado (IDOR, não-empresário),
integridade de arquivos (SHA-256), moderação por IA, ataques simulados e os alertas da IA de anomalias. O
histórico de `logs/security.log` pode ser importado.

**Volume.** Um gerador sintético cria tráfego normal (com mais atividade em horário comercial) e injeta os cinco
tipos de anomalia citados no enunciado. Com 50 mil eventos, a geração leva ~9 s e a análise com exportação CSV,
~3 s.

**Processamento.** `analise_eventos.py` entrega resumos, séries temporais, rankings e as **features por janela**
(uma linha por IP e janela de 5 minutos), que são a entrada da IA.

## 5. IA de detecção de anomalias

**Algoritmo.** Detector híbrido, no mesmo desenho de um SIEM:

1. **Regras de assinatura:** limiares por janela de 5 min (≥ 10 falhas de login, ≥ 10 falhas de decifragem,
   ≥ 10 acessos negados, ≥ 100 eventos, qualquer arquivo alterado). Alta precisão, mas só pegam o que alguém
   previu.
2. **Isolation Forest** (scikit-learn, não supervisionado): aprende o comportamento normal a partir dos próprios
   dados, sem rótulos, e pontua cada janela de 0 a 1 pela facilidade com que ela é isolada das demais. Pega
   combinações que nenhuma regra descreve.

Cada alerta é gravado como evento `anomalia`, com severidade (`critico` para regra ou pontuação ≥ 0,70,
`alerta` para o resto), método, pontuação e as 3 features que mais se desviaram do normal, com o valor e a
mediana. Isso é o que torna o alerta explicável.

**Testes.** 17 testes automatizados, entre eles: regras sem o modelo; o modelo pegando uma combinação abaixo de
todos os limiares; reprodutibilidade; idempotência (rodar duas vezes não duplica); os alertas não contaminam a
próxima execução; e o controle de acesso ao painel.

**Resultados.** Avaliação contra o gabarito dos dados sintéticos. Calibração na semente 42; validação em 5
sementes novas, sem reajuste (média):

| Abordagem | Precisão | Recall | F1 |
|---|---|---|---|
| Só regras | 1,000 | 0,813 | 0,896 |
| Só Isolation Forest | 0,836 | 0,769 | 0,800 |
| **Híbrido** | **0,851** | **0,867** | **0,858** |

| Anomalia do enunciado | Detectado (híbrido) | Quem pegou melhor |
|---|---|---|
| Número incomum de tentativas de autenticação | 88% | Isolation Forest (88%) × regras (78%) |
| Comportamento incomum na geração de eventos | 76% | Isolation Forest (76%) × regras (61%) |
| Alterações inesperadas em arquivos | 100% | regras (100%) × Isolation Forest (37%) |
| Frequência elevada de falhas de descriptografia | 94% | empate |
| Padrões atípicos de acesso | 82% | empate |

O modelo ganha nas **bordas dos ataques**: quando uma rajada atravessa a fronteira entre janelas, sobra um
pedaço abaixo do limiar da regra que, ainda assim, é raro. As regras são indispensáveis para arquivo alterado,
um evento pequeno demais para parecer estatisticamente raro. O custo do híbrido são ~5 falsos positivos por
rodada de 50 mil eventos, todos de severidade `alerta`.

**Limitações.** Dados sintéticos com ataques conhecidos (o que favorece as regras); contaminação fixa (o modelo
sempre aponta ~3% das janelas ativas); fragmentos com menos de 3 eventos não são detectados. Detalhes:
[IA_ANOMALIAS.md](IA_ANOMALIAS.md).

## 6. Dashboard

`/painel-seguranca/`, restrito à equipe (`is_staff`). Mostra indicadores, falhas e anomalias no tempo, anomalias
por motivo e por método, o veredito de cada ataque à cifra, a tabela de anomalias recentes com a explicação de
cada uma, e o ranking de IPs suspeitos. Quem tenta abrir o painel sem permissão recebe 403, e a tentativa vira
evento. Os dados chegam ao navegador escapados (sem risco de XSS por dado do banco), o Chart.js é carregado com
Subresource Integrity e a página respeita a Content Security Policy do projeto. Detalhes:
[PAINEL_SEGURANCA.md](PAINEL_SEGURANCA.md).

![Anomalias recentes no painel](../evidencias/08-painel-seguranca/2-anomalias-recentes.jpg)

---

## Conclusão

1. **Os ataques mostraram o que faltava na cifra, e a correção foi validada pelos mesmos ataques.** A primeira
   versão tinha chave dinâmica, XOR, substituição, permutação, blocos e encadeamento, e passava no teste
   estatístico. Mas a falta de mistura entre os bytes do bloco eliminava o efeito avalanche e permitia recuperar
   a chave em ~1 s com texto conhecido. A versão 2 acrescentou mistura de colunas, chave de 128 bits e
   autenticação HMAC, e passou a guardar a chave cifrada. Rodados de novo, os ataques mostram avalanche de 50%,
   o ataque byte a byte deixa de se aplicar e a adulteração é rejeitada. Para dado real, a recomendação continua
   sendo AES-GCM ou Fernet, que o projeto já usa nas reservas.
2. **Registrar eventos estruturados é o que torna a detecção possível.** Antes, os eventos eram linhas de texto
   num arquivo de log. Com a tabela, a mesma informação vira features por janela, séries temporais e alertas
   explicáveis.
3. **Regras e IA se complementam.** As regras dão precisão e explicação imediata para o ataque conhecido. O
   Isolation Forest aumenta o recall onde a regra é cega, sem nenhum limiar escrito à mão. O detector híbrido
   teve o melhor recall (0,867) com precisão de 0,851.
4. **Próximos passos.** Agendar a IA para processar só as janelas novas e, na esteganografia, espalhar os bits
   em posições sorteadas a partir da chave.

## Como reproduzir tudo

Dentro de `projeto/`:

```bash
pip install -r requirements-ia.txt
python manage.py migrate
python manage.py gerar_eventos_simulados --qtd 50000 --seed 1
python manage.py rodar_ataques
python manage.py demonstrar_esteganografia
python manage.py detectar_anomalias --avaliar
python manage.py test apps
python manage.py runserver            # painel em /painel-seguranca/ (usuário is_staff)
```
