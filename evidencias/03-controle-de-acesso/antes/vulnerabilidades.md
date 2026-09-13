# Evidência — Vulnerabilidades (ANTES)

**Tema:** Controle de acesso (autorização/autenticação) — OWASP A01:2021
(Broken Access Control) e A07:2021 (Identification and Authentication Failures).
**Componente:** `apps/views.py`.

## 1. IDOR — autorização em nível de objeto quebrada (CRÍTICO / CWE-639)

As views de editar e excluir reserva carregavam o objeto **apenas pelo id da
URL**, sem verificar se a reserva pertence ao usuário logado:

```python
@login_required
def editar_reserva(request, reserva_id):
    reserva = get_object_or_404(ReservaCafe, id=reserva_id)   # <-- sem dono
    ...

@login_required
def excluir_reserva(request, reserva_id):
    reserva = get_object_or_404(ReservaCafe, id=reserva_id)   # <-- sem dono
```

**Ataque:** qualquer usuário autenticado troca o `reserva_id` na URL
(`/editar_reserva/<id>/`, `/excluir_reserva/<id>/`) e **edita ou apaga reservas
de outros clientes**. `@login_required` só garante que existe *alguém* logado,
não que é o *dono*. A view `cancelar_reserva` já fazia certo
(`cliente__email=request.user.email`) — as outras duas ficaram inconsistentes.

## 2. `@login_required` faltando (CWE-306)

- `editar_cadastro_cafe` **não tinha `@login_required`** e acessava
  `request.user.usercliente`. Para um visitante anônimo (`AnonymousUser`), isso
  lança `AttributeError` → **HTTP 500** (falha suja) em vez de redirecionar ao
  login.
- `enviar_email` **não tinha `@login_required`** (enquanto `enviar_whatsapp`
  tinha). Um anônimo podia disparar e-mails para qualquer cafeteria →
  **vetor de spam/abuso** em nome da aplicação.

## 3. Enumeração de usuários no login (CWE-204)

O login devolvia mensagens **diferentes** para "e-mail não cadastrado" e "senha
errada":

```python
except ObjectDoesNotExist:
    return render(request, 'login.html', {'error': 'Usuário não encontrado'})
...
    return render(request, 'login.html', {'error': 'Usuário ou senha inválidos'})
```

**Ataque:** um atacante testa e-mails e descobre **quais estão cadastrados**
(mensagem "Usuário não encontrado" vs "senha inválida") — útil para phishing e
força-bruta direcionada. Além disso, `User.objects.get(email=...)` podia lançar
`MultipleObjectsReturned` (o e-mail não é único no `User` padrão do Django) →
HTTP 500.
