# Evidência — Correção (DEPOIS)

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

**Por que estes campos (e não senha/e-mail)?**
- Senha **não** deve ser cifrada e sim *hasheada* — o Django já faz isso via
  `create_user()`. Cifrar senha seria anti-padrão.
- `email`/`whatsapp`/`cnpj` são usados em **filtros de igualdade e `unique`**.
  Como o Fernet é não determinístico, cifrá-los quebraria buscas e unicidade.
  Já `nome_cliente`/`observacao` só são **exibidos**, nunca consultados por valor
  — são o alvo seguro e de maior valor de PII.

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
