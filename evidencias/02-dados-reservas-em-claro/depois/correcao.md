# Evidência — Correção (DEPOIS)

> **Atualização:** este documento registra a Rodada 1 da correção (só
> `ReservaCafe`). Numa rodada seguinte a criptografia foi **estendida** para
> `UserCliente.email` e `Cafe.email`/`whatsapp`/`cnpj` — os mesmos campos que
> a seção "Por que estes campos" abaixo explica que, *na época*, não
> podiam ser cifrados por serem usados em busca/unicidade. Isso deixou de ser
> um bloqueio: ver a seção **"Atualização — blind index"** no final deste
> arquivo para o mecanismo que resolveu isso sem quebrar login nem checagem
> de duplicidade.

**Vulnerabilidade:** Dados pessoais em texto puro (sem criptografia em repouso).
**Componente:** `apps/crypto_fields.py`, `apps/models.py` (`ReservaCafe`).

## Correção aplicada: criptografia SIMÉTRICA de campo em repouso

Os campos `nome_cliente` e `observacao` da `ReservaCafe` passaram a ser cifrados
em repouso com **Fernet** (biblioteca `cryptography`): **AES-128-CBC + HMAC-SHA256**,
com **IV aleatório por mensagem**. A cifragem/decifragem é transparente para a
aplicação (campos customizados `EncryptedCharField`/`EncryptedTextField`).

```python
# apps/models.py
from .crypto_fields import EncryptedCharField, EncryptedTextField

class ReservaCafe(models.Model):
    ...
    nome_cliente = EncryptedCharField(blank=True, null=True)
    ...
    observacao   = EncryptedTextField(blank=False, default='Descrição não informada')
```

## Justificativa das escolhas

**Por que simétrica e não assimétrica (RSA/ECC)?**
A mesma aplicação precisa TANTO gravar QUANTO ler esses dados em operações
rotineiras (mostrar a reserva ao cliente e ao dono da cafeteria). Criptografia
assimétrica só se justifica quando quem cifra e quem decifra são partes distintas,
ou quando se quer que o serviço apenas cifre e nunca leia — não é o caso. Além
disso, RSA não é adequado para texto livre (limite de tamanho por bloco) e é mais
lento, sem ganho de modelo de ameaça aqui. Logo, **criptografia simétrica
autenticada é a escolha correta**.

**Por que Fernet/AES?** Entrega, de uma vez:
- **Confidencialidade** — o texto não é legível no banco;
- **Integridade/autenticidade** — adulteração do ciphertext é detectada (HMAC),
  em vez de decifrar lixo silenciosamente;
- **IV aleatório** — o mesmo texto gera ciphertexts diferentes, evitando
  vazamento de padrões (ex.: descobrir que duas reservas têm o mesmo nome).

**Por que estes campos primeiro (e não senha/e-mail)?**
- Senha **não** deve ser cifrada e sim *hasheada* — o Django já faz isso via
  `create_user()`. Cifrar senha seria anti-padrão. Isso não mudou e não muda.
- Nesta Rodada 1, `email`/`whatsapp`/`cnpj` foram deixados de fora porque são
  usados em **filtros de igualdade e `unique`**, e o Fernet é não
  determinístico — cifrar direto quebraria login e checagem de duplicidade.
  `nome_cliente`/`observacao` só são **exibidos**, nunca consultados por
  valor, então eram o alvo sem esse problema — por isso entraram primeiro.
  (Esse bloqueio foi resolvido numa rodada seguinte, ver atualização no final
  deste arquivo — não é mais motivo para deixá-los em claro.)

**Gestão da chave.** A chave (`FIELD_ENCRYPTION_KEY`) vive **fora do banco**, em
variável de ambiente (`projeto.env`, que é gitignored), separando o dado do
segredo que o protege. Assim, **um dump do banco não basta** para ler os dados.

## Provas de teste (mesmo dado, antes vs. depois no banco)

Dado gravado: `nome_cliente="Maria da Silva Sauro"`,
`observacao="Alergia a lactose. Mesa perto da janela, por favor."`

**1) O que fica gravado no banco (SQL cru, sem ORM):**
```
nome_cliente = 'gAAAAABqprWa7lHQeh4k56W28iUYUvB5ExgF3juTVUrQOtgozT2TjP5H1jSp0t4irzV8YNyDW_A4Xk9IXX4PANNlhEnZ6a4nqSIOuiaHYSqrDuD7dvjdPCk='
observacao   = 'gAAAAABqprWaET10M333YOQ8tI82oT2d1wrDq8vAV8KzW0PatLyqJNyn0BeuwmzO3AkszuKuIlpu3awmHGVXa5WHUgtChjj-rbqcnR-czu_kuuuhOF8B-wE3fjzw2dI2v8ydw1AcIz2pH88aMrMDoVOzkTVZXTAsog=='
```
→ Dados **não** aparecem em claro; são tokens Fernet (`gAAAA...`).

**2) O que a aplicação lê (via ORM, decifra transparente):**
```
nome_cliente = 'Maria da Silva Sauro'
observacao   = 'Alergia a lactose. Mesa perto da janela, por favor.'
```
→ A aplicação recupera o texto original normalmente.

**3) IV aleatório** — dois registros com `nome_cliente="IGUAL"` produzem
ciphertexts **diferentes** no banco. OK.

**4) Detecção de adulteração** — alterar 1 caractere do ciphertext no banco faz a
leitura falhar com `InvalidToken` (HMAC), em vez de aceitar dado corrompido. OK.

**5) Compatibilidade com dado legado** — linhas antigas em claro continuam
legíveis (fallback) e o comando `python manage.py encrypt_existing_data` as
migra para ciphertext de forma idempotente:
```
Reservas: 3 | já cifradas: 0 | a cifrar: 3
3 reserva(s) cifrada(s) em repouso com sucesso.
```

`python manage.py check` → *System check identified no issues*.

## Arquivos alterados / adicionados

- `apps/crypto_fields.py` — campos criptografados + justificativa (novo);
- `apps/models.py` — `ReservaCafe.nome_cliente`/`observacao` cifrados;
- `apps/management/commands/encrypt_existing_data.py` — migra dados legados (novo);
- `apps/migrations/0049_alter_reservacafe_nome_cliente_and_more.py` — migração;
- `g3/settings.py` + `projeto.env.example` — `FIELD_ENCRYPTION_KEY`;
- `requirements.txt` — dependência `cryptography`.

## Como configurar

```bash
# 1. gerar a chave
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# 2. colocar em projeto.env
FIELD_ENCRYPTION_KEY=<chave_gerada>
# 3. aplicar
pip install -r requirements.txt
python manage.py migrate
python manage.py encrypt_existing_data   # cifra reservas pré-existentes
```

---

## Atualização — blind index (Rodada 2: email, CNPJ, whatsapp)

O bloqueio descrito acima ("Fernet não determinístico quebra busca/unicidade")
foi resolvido sem abandonar a cifra nesses campos. `UserCliente.email` e
`Cafe.email`/`whatsapp`/`cnpj` agora **também são `EncryptedCharField`**, e
cada um ganhou uma coluna extra `*_hash` (`email_hash`, `cnpj_hash`,
`whatsapp_hash`) com um **HMAC-SHA256 determinístico** do valor normalizado,
usando a mesma `FIELD_ENCRYPTION_KEY` como chave do HMAC (`apps/crypto_fields.py`,
função `calcular_hash_busca`).

**Por que isso resolve o bloqueio:** Fernet continua não-determinístico (é o
que garante a propriedade de IV aleatório desta correção) — mas o HMAC, com
chave fixa, é **determinístico**: o mesmo e-mail sempre gera o mesmo hash.
Login, cadastro e checagem de duplicidade passaram a comparar pelo hash
(`.filter(email_hash=...)`), nunca pelo valor cifrado. O hash não reintroduz
o texto em claro — só permite comparar igualdade, nunca recuperar o valor
original a partir dele (ao contrário de reverter o Fernet, que exige a chave
E devolve o texto original).

**Prova (dado real, cru vs. decifrado):**
```
-- UserCliente, coluna email (cru, sem ORM):
email      = 'gAAAAABqq90LCSnLIvcNKhqrPcS15UOvNXaCqatCsDONCVV9Oe629_9tLnnDLs9QG4EubNdgupTyqL_yWu_39puBgEeOhlAy8JDKKE9Qsxuwt8lY8cMXm2nc2hBMdG3wE875NmSEN19Q'
email_hash = 'b58bfcc96ae79fcc0d5acb897eb43d620e9d8b9ae6262e242d6e43f54adbedb2'

-- Cafe, colunas cnpj/whatsapp (cru, sem ORM):
cnpj          = 'gAAAAABqq90LaskOjKdNaU447f7Wt7ci_1hrkVZC4nTo4nEMrFVGTExN-KF-Ztpsdsurck8zOPZewXJjlh61kWoqkH4hpEuv3g=='
cnpj_hash     = 'adc0e3cc582e0210769b02201763b8b48914d6f9f3ced67cac50d69b5d5b1600'
whatsapp      = 'gAAAAABqq90LYikcdpbTG5tOl4_E3ZbZ0O6tykyWaUeGc-7J8L-UnLz95WlUTcb5A_KQCjQhULnwnlGD4BADAeC4so2SOK3r1Q=='
whatsapp_hash = '92458bdbbc2afcd13712ab575a79fcbc3f4ee3dac3614b33c6a623efa5d93acf'

-- Via ORM (decifrado transparente):
email    = 'maria.julia@apontecafes.local'
cnpj     = '10000000000101'
whatsapp = '5581999000001'
```

**O que passou a usar o hash em vez do valor em claro** (`apps/views.py`,
`apps/management/commands/seed_fake_data.py`): checagem de e-mail duplicado
no cadastro e na edição de perfil; checagem de CNPJ/whatsapp duplicado no
cadastro e edição de cafeteria; limpeza/reset dos dados de seed.

**O que passou a usar a FK em vez do e-mail** (dispensando o hash de todo):
toda consulta do tipo "minha própria reserva"/"meu próprio perfil" trocou
`cliente__email=request.user.email` por `cliente__user=request.user` — join
direto pela chave estrangeira já existente, sem precisar tocar em campo
cifrado nem em hash. Mais simples e mais direto do que parece à primeira
vista: nem todo lookup por e-mail precisava do blind index, só os que
comparam contra **todos** os registros (checagem de duplicidade), não os que
já sabem exatamente qual usuário é.

**Reteste (mesmo espírito do item 5 acima, agora para os 3 campos novos):**
```
$ python manage.py encrypt_existing_data --dry-run
UserCliente: 30 | já cifradas: 30 | a cifrar: 0
Cafe: 6 | já cifradas: 6 | a cifrar: 0
Avaliacao: 8 | já cifradas: 8 | a cifrar: 0
ReservaCafe: 4 | já cifradas: 4 | a cifrar: 0
```

### Arquivos alterados/adicionados nesta rodada
- `apps/crypto_fields.py` — `calcular_hash_busca` (blind index) + log de aviso
  no fallback de dado legado;
- `apps/models.py` — `UserCliente.email`/`nome_completo`, `Cafe.responsavel`/
  `endereco`/`email`/`whatsapp`/`cnpj`, `Avaliacao.comentario`/`valor_gasto`
  cifrados; campos `email_hash`/`cnpj_hash`/`whatsapp_hash`; remoção de
  `UserCliente.password`/`confirm_password` (nunca usados, ver seção de
  autenticação do relatório);
- `apps/views.py` — lookups por e-mail/CNPJ/whatsapp trocados por hash ou FK;
- `apps/management/commands/seed_fake_data.py` — mesmos lookups corrigidos;
- `apps/management/commands/encrypt_existing_data.py` — generalizado para
  todos os modelos cifrados (antes só `ReservaCafe`);
- `apps/migrations/0052_remove_usercliente_confirm_password_and_more.py`,
  `0053_alter_cafe_cnpj_hash_alter_cafe_whatsapp_hash_and_more.py` — schema +
  backfill de hash + cifragem de dado legado em uma migração de dados.
