# Evidência — CSRF em ação de estado via GET (ANTES)

**Vulnerabilidade:** Ação que altera estado (favoritar/desfavoritar) aceitava
requisição `GET` — CWE-352 (Cross-Site Request Forgery) / OWASP A01:2021
(Broken Access Control, uso indevido de método HTTP seguro para operação
não-idempotente).
**Componente:** `apps/views.py`, função `favoritar`.

## Código vulnerável

```python
@login_required
def favoritar(request, cafe_id):
    cafe = get_object_or_404(Cafe, id=cafe_id)

    if request.method == 'POST' or request.method == 'GET':
        usuario = request.user
        ...
```

## Método de exploração

`GET` é considerado um método "seguro" pela especificação HTTP (não deveria
ter efeito colateral) — por isso navegadores e diversos mecanismos de
proteção (inclusive o próprio Django, cujo middleware de CSRF só valida
`POST`/`PUT`/`PATCH`/`DELETE`) não protegem requisições `GET` contra
falsificação entre sites. Como `favoritar` processava `GET` como se fosse
`POST`, um atacante podia embutir a ação em qualquer página de terceiro sem
precisar de JavaScript nem de token CSRF:

```html
<img src="https://<host-da-aplicacao>/favoritar/7" style="display:none">
```

Se a vítima (com sessão ativa na aplicação) visitasse essa página, o
navegador carregaria a "imagem" automaticamente, disparando um `GET`
autenticado (via cookie de sessão) que favoritava/desfavoritava uma
cafeteria sem nenhuma ação consciente da vítima.

## Impacto

Baixo/médio: a pior consequência é favoritar ou desfavoritar cafeterias sem
consentimento do usuário (nenhum dado sensível é lido ou vazado, nenhuma
conta é comprometida). Foi corrigido mesmo assim porque é uma violação clara
do princípio "ação que muda estado exige método que exige CSRF token",
mesma categoria de falha que, em outro endpoint com consequência mais
grave, seria crítica.
