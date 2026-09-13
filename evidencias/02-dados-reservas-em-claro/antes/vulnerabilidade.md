# Evidência — Vulnerabilidade (ANTES)

**Vulnerabilidade:** Dados pessoais sensíveis armazenados em texto puro (falta de
criptografia em repouso) — CWE-311 (Missing Encryption of Sensitive Data) /
OWASP A02:2021 (Cryptographic Failures).
**Componente:** modelo `ReservaCafe` (`apps/models.py`), campos `nome_cliente`
e `observacao`.

## Descrição

As reservas guardam **dados pessoais dos clientes em claro** no banco:

- `nome_cliente` — nome de quem vai à cafeteria;
- `observacao` — texto livre que frequentemente contém dado sensível (ex.:
  *"alergia a lactose"*, *"cadeirante, preciso de mesa acessível"*, telefone,
  etc.).

Combinados com `cafe`, `data_reserva` e `horario_reserva`, esses campos revelam
**quem estará em qual lugar, em qual dia e horário** — um dado de localização/
comportamento sensível.

Definição original do modelo:

```python
class ReservaCafe(models.Model):
    ...
    nome_cliente = models.CharField(max_length=100, blank=True, null=True)
    ...
    observacao = models.TextField(blank=False, default='Descrição não informada')
```

## Impacto / cenário de ataque

O produto é hospedado com **PostgreSQL no Azure** (ver README). Qualquer cenário
que exponha o banco — dump/backup vazado, credencial de banco comprometida,
snapshot mal configurado, acesso de um administrador curioso — entrega **todos
esses dados pessoais legíveis em texto puro**, sem nenhuma barreira adicional.

Exemplo de como os dados apareciam num dump/`SELECT` do banco:

```
sqlite> SELECT nome_cliente, observacao FROM apps_reservacafe LIMIT 1;
Maria da Silva Sauro|Alergia a lactose. Mesa perto da janela, por favor.
```

Ou seja: **o dado sensível está imediatamente legível para quem tiver o banco**.

## Por que hash não resolve aqui

Hash (como o usado em senhas) é irreversível — serve para *verificar*, não para
*recuperar*. Mas a aplicação **precisa exibir** o nome e a observação de volta ao
cliente e ao dono da cafeteria. Portanto o dado precisa ser **reversível**, o que
exige **criptografia** (e não hash). A correção usa criptografia simétrica
autenticada (ver `../depois/correcao.md`).
