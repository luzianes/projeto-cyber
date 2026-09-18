# Evidência — Correção (DEPOIS)

**Tema:** Controle de acesso (autorização/autenticação).
**Componente:** `apps/views.py` (+ testes de regressão em `apps/tests.py`).

## Correções aplicadas

### 1. IDOR corrigido — autorização em nível de objeto
`editar_reserva` e `excluir_reserva` passaram a carregar a reserva **filtrando
pelo dono**, seguindo o padrão que `cancelar_reserva` já usava:

```python
# antes
reserva = get_object_or_404(ReservaCafe, id=reserva_id)
# depois (nesta rodada)
reserva = get_object_or_404(ReservaCafe, id=reserva_id,
                            cliente__email=request.user.email)
```

Agora, se o usuário logado não é o dono, o objeto simplesmente **não é
encontrado** (HTTP 404) — ele não consegue nem ler, nem editar, nem excluir a
reserva alheia.

> **Atualização:** numa rodada posterior, quando `UserCliente.email` passou a
> ser cifrado (ver `evidencias/02-dados-reservas-em-claro/depois/`, seção
> "Atualização — blind index"), esse filtro deixou de funcionar por valor de
> e-mail e foi trocado por `cliente__user=request.user` — join direto pela
> chave estrangeira, que já identifica o dono sem depender de um campo
> cifrado. A garantia de autorização (só o dono acessa) é a mesma; só o
> mecanismo de comparação mudou.

### 2. `@login_required` adicionado
Adicionado o decorator em `editar_cadastro_cafe` e em `enviar_email`. Visitantes
anônimos agora são **redirecionados ao login** (HTTP 302) em vez de causar 500
(no caso da cafeteria) ou de conseguir disparar e-mails (no caso do e-mail).

### 3. Login sem enumeração de usuários
E-mail inexistente e senha errada passam a devolver **a mesma mensagem
genérica** ("E-mail ou senha inválidos."), e o `MultipleObjectsReturned` é
tratado (sem 500):

```python
credenciais_invalidas = 'Usuario ou senha invalidos.'
try:
    username = User.objects.get(email__iexact=email).username
except (ObjectDoesNotExist, User.MultipleObjectsReturned):
    return render(request, 'login.html', {'error': credenciais_invalidas})
...
else:
    return render(request, 'login.html', {'error': credenciais_invalidas})
```

> Observação: a mensagem genérica remove a enumeração *explícita*. Um endurecimento
> adicional (fora do escopo desta rodada) seria uniformizar também o tempo de
> resposta para não vazar a existência do e-mail por *timing*.

## Provas de teste (regressão automatizada)

Adicionados 6 testes em `apps/tests.py` (`ControleAcessoTests`). Execução:

```
$ python manage.py test apps
test_dono_edita_e_exclui_a_propria_reserva ... ok
test_editar_cadastro_cafe_exige_login ... ok
test_editar_reserva_de_outro_usuario_e_bloqueado ... ok
test_enviar_email_exige_login ... ok
test_excluir_reserva_de_outro_usuario_e_bloqueado ... ok
test_login_nao_diferencia_email_inexistente_de_senha_errada ... ok
----------------------------------------------------------------------
Ran 6 tests in 1.291s
OK
```

O que cada teste prova:
- **IDOR bloqueado:** logado como "bob", GET em `editar_reserva` da reserva de
  "alice" → 404; POST em `excluir_reserva` → 404 **e a reserva continua existindo**.
- **Dono mantém acesso:** logado como "alice", edita (200) e exclui (302) a
  própria reserva normalmente.
- **Auth exigida:** anônimo em `editar_cadastro`/`enviar-email` → 302 para `/login`.
- **Anti-enumeração:** e-mail inexistente e senha errada retornam a mesma
  mensagem, sem "Usuário não encontrado".

## Reteste em navegador real (Playwright), com capturas de tela

Além da suíte automatizada acima, os mesmos cenários foram reproduzidos num
navegador de verdade contra a aplicação rodando localmente, com contas de
teste reais (`ana.bezerra@apontecafes.local`, dona da reserva `id=1`, e
`bruno.lima@apontecafes.local`, dono da reserva `id=2`):

1. **IDOR bloqueado:** logada como ana_bezerra, acesso a
   `/editar_reserva/2/` (reserva de bruno_lima) → `3-idor-bloqueado-404.png`
   (HTTP 404, sem vazar que a reserva existe)
2. **Dono acessa normalmente:** ana_bezerra em `/editar_reserva/1/` (a
   própria reserva) → `4-dono-acessa-propria-reserva.png` (HTTP 200)
3. **Anônimo redirecionado:** acesso sem login a `/cafeteria/1/editar/` →
   `5-anonimo-redirecionado-login.png` (redireciona para
   `/login/?next=/cafeteria/1/editar/`)

Log bruto dos status HTTP capturados: `log-requisicoes.txt`.

## Arquivos alterados

- `apps/views.py` — `editar_reserva`, `excluir_reserva` (filtro por dono);
  `editar_cadastro_cafe`, `enviar_email` (`@login_required`); `login_view`
  (mensagem genérica).
- `apps/tests.py` — `ControleAcessoTests` (6 testes de regressão).

## Fora do escopo desta rodada (registrado para depois)

- ~~`favoritar` aceita **GET** para operação que altera estado (CSRF via `<img>`);
  ideal torná-la POST-only.~~ **Corrigido numa rodada posterior** — ver
  `evidencias/04-favoritar-csrf-get/`.
- ~~`print()` de sessão/ID/grupos em várias views → remover (info disclosure).~~
  **Corrigido numa rodada posterior** — `print()`s de depuração removidos de
  `apps/views.py` (um deles imprimia o conteúdo inteiro da sessão a cada
  requisição para `/cadastro_cafeteria`).
