# SecureAI Lab — Aponte Cafés

Projeto da disciplina **Cibersegurança Aplicada a Dados e IA** (CESAR School), que reaproveita
o **Aponte Cafés**, aplicação Django de descoberta e avaliação de cafeterias, originalmente
desenvolvida na disciplina de Projetos 2, e a instrumenta com mecanismos de segurança,
seguindo o ciclo **Desenvolvimento → Análise → Exploração → Correção → Reteste**.

## Descrição da aplicação

O Aponte Cafés ajuda usuários a descobrir e avaliar cafeterias no Centro do Recife. Existem
dois tipos de usuário: **cliente** (busca, favorita, reserva horário, avalia) e **empresário**
(cadastra e administra a própria cafeteria).

### Funcionalidades

- Buscar e visualizar cafeterias (localização, horário, contato)
- Cadastro e edição de perfil de usuário
- Cadastro e edição de cafeteria (empresário)
- Favoritar cafeterias e consultar/editar a lista
- Reservar horário, consultar/editar/cancelar reservas
- Avaliar cafeterias (nota, comentário, foto), com **moderação automática por IA**
- Histórico de cafeterias visitadas

## Segurança implementada

| Área | O que foi feito |
|---|---|
| **Autenticação e autorização** | 2 níveis de privilégio via grupo Django ("Empresários" x cliente), política de senha customizada, fluxo de redefinição de senha, login sem enumeração de usuário, correção de IDOR em reservas |
| **Criptografia** | Campos sensíveis da reserva (`nome_cliente`, `observacao`) cifrados em repouso com Fernet (AES-128-CBC + HMAC-SHA256); senha de usuário com hash nativo do Django (PBKDF2) |
| **Integridade** | Hash SHA-256 calculado no upload de fotos (perfil, cafeteria, avaliação) para detectar adulteração |
| **API** | Endpoints JSON próprios (`/api/cafeterias/` público, `/api/minhas-reservas/` autenticado e filtrado por dono) |
| **HTTPS** | Redirecionamento forçado e HSTS habilitados em produção |
| **Segredos** | Nenhuma chave/senha no código-fonte — tudo via variável de ambiente (`projeto.env`, fora do Git) |
| **Logs de segurança** | Login, acesso negado e decisões de moderação por IA registrados em `projeto/logs/security.log` |
| **Segurança de IA** | Moderação de avaliações via API do Gemini; vulnerabilidade de *prompt injection* identificada, explorada e corrigida (isolamento instrução/dado + saída estruturada) |

Evidências completas (antes/depois de cada vulnerabilidade) estão em [evidencias/](evidencias/).
Vulnerabilidades ainda em aberto e decisões técnicas justificadas ficam no relatório técnico do
projeto (fora deste repositório).

## Tecnologias

- **Back-end**: Django (Python), sem uso de Django Forms nem Generic Views
- **Front-end**: HTML, CSS, JavaScript
- **Banco de dados**: PostgreSQL (local via Docker, ou Azure em produção); SQLite como alternativa em dev
- **IA**: API do Google Gemini (moderação de avaliações)
- **Hospedagem**: Microsoft Azure (App Service)

## Como rodar localmente

1. Copie `projeto.env.example` para `projeto.env` (raiz do repositório) e preencha os valores (veja os comentários no próprio arquivo). No mínimo, gere um `SECRET_KEY` novo; para usar a
   moderação por IA, gere uma `GEMINI_API_KEY` gratuita em
   [aistudio.google.com/apikey](https://aistudio.google.com/apikey).

2. Suba o Postgres local via Docker (a partir da raiz do repositório):

   ```bash
   docker compose --env-file projeto.env up -d db
   ```

3. Instale as dependências e rode as migrations:

   ```bash
   cd projeto
   python -m venv .venv
   .venv/Scripts/python -m pip install -r requirements.txt   # Windows
   # .venv/bin/python -m pip install -r requirements.txt     # Linux/WSL/macOS
   .venv/Scripts/python manage.py migrate
   .venv/Scripts/python manage.py seed_fake_data --reset      # dados fictícios
   .venv/Scripts/python manage.py runserver
   ```

## Equipe

**SecureAI Lab (Cibersegurança)**:

- [Davi Gomes](https://github.com/daviruy61)
- [Lisa Matubara](https://github.com/lilymtbr)
- [Luana Falcão](https://github.com/lua-mf)
- [Luziane Santos](https://github.com/luzianes)
- [Maria Júlia Peixoto](https://github.com/majupeixoto)
- [Paulo Rago](https://github.com/paulo-rago)

**Projeto original (Projetos 2)**:

- [Arthur Borges](https://github.com/borgearthur)
- [Beatriz Pereira](https://github.com/biapereira2)
- [Lisa Matubara](https://github.com/lilymtbr)
- [Luziane Santos](https://github.com/luzianes)
- [Manuela Cavalcanti](https://github.com/Manuelaamorim)
- [Matheus Velame](https://github.com/MatheusVelame)
- [Matheus Cazé](https://github.com/ogcaze)
- [Thaís Aguiar](https://github.com/aguiarth)
- [Ygor Rosa](https://github.com/YgoRosa)

## Histórico do projeto original

Entregas do projeto original (disciplina de Projetos 2): [SR1.md](SR1.md) e [SR2.md](SR2.md).

## Licença

Este projeto é licenciado sob a [MIT License](https://opensource.org/licenses/MIT).
