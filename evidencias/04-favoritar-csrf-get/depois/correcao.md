# Evidência — Correção e Reteste (DEPOIS)

**Vulnerabilidade:** CSRF em ação de estado via GET (`favoritar`).
**Componente:** `apps/views.py`; templates `detalhes.html`, `favoritos.html`,
`home.html`, `historico.html`.

## Correção aplicada

1. **View exige `POST`.**

```python
@login_required
def favoritar(request, cafe_id):
    cafe = get_object_or_404(Cafe, id=cafe_id)

    if request.method == 'POST':
        usuario = request.user
        ...
    return redirect('home')
```

2. **Os dois lugares com `<a href="{% url 'favoritar' %}">` (GET puro)**
   viraram `<form method="post">` com `{% csrf_token %}` (`detalhes.html`,
   `favoritos.html`).
3. **As duas versões via AJAX** (`home.html`, `historico.html`) trocaram
   `method: 'GET'` por `method: 'POST'`, adicionando o header
   `X-CSRFToken` lido do cookie `csrftoken` via uma função `getCookie()`.

## Reteste — evidência real, capturada em navegador de verdade (Playwright)

Diferente da exploração anterior (que era só teórica, com o `<img>` de
exemplo), o reteste abaixo foi executado de fato contra a aplicação rodando
localmente, com Chromium controlado por Playwright, partindo de um estado
conhecido (cafeteria "Grao do Patio" **não favoritada** pela conta de
teste `ana.bezerra@apontecafes.local`).

**1) Estado inicial — não favoritado:**
`1-estado-inicial-nao-favoritado.png` — botão mostra "Favoritar".

**2) `GET` direto na URL `/favoritar/2`** (equivalente ao `<img>` da seção
"antes") **— sem efeito:**

```
GET direto na URL /favoritar/2 -> status 200, redirecionou para: http://127.0.0.1:8000/
Estado do botao APOS o GET direto: "Favoritar" (sem mudanca)
```

`2-apos-get-direto-continua-nao-favoritado.png` confirma visualmente: o
botão continua mostrando "Favoritar" (coração vazio) — a ação **não**
mudou o estado no banco.

**3) `POST` real (clique no botão, com token CSRF) — funciona normalmente:**

```
Apos clicar de verdade (POST), pagina redirecionou para: http://127.0.0.1:8000/favoritos/
Estado do botao APOS o POST real: "Desfavoritar" (mudou)
```

`3-apos-post-real-favoritado.png` confirma: o botão passou a mostrar
"Desfavoritar" (coração preenchido) — o favorito foi de fato criado no
banco (`Favorito.objects.filter(usuario=ana_bezerra, cafe_id=2).exists()`
→ `True`).

**Antes:** `GET` favoritava. **Depois:** `GET` não tem efeito nenhum; só
`POST` com token CSRF válido consegue alterar o estado. Ataque bloqueado.

## Arquivos desta evidência

- `1-estado-inicial-nao-favoritado.png`
- `2-apos-get-direto-continua-nao-favoritado.png`
- `3-apos-post-real-favoritado.png`
- `log-requisicoes.txt` — log bruto das requisições HTTP capturadas durante
  o reteste (método, URL, status).

## Arquivos alterados na correção

- `apps/views.py` — `favoritar` só processa `POST`.
- `apps/templates/detalhes.html`, `apps/templates/favoritos.html` —
  `<a href>` → `<form method="post">` com `{% csrf_token %}`.
- `apps/templates/home.html`, `apps/templates/historico.html` — AJAX
  `GET` → `POST` com header `X-CSRFToken`.
