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

### Banco pronto com Docker Compose

Com o Docker instalado e em execução, rode na raiz do repositório:

```bash
docker compose up
```

O Compose inicia o PostgreSQL, aguarda o banco aceitar conexões e executa o serviço
`db-init`, que aplica as migrations e carrega os dados fictícios **somente se o banco
estiver vazio**. Ao aparecer `Banco pronto para uso.`, o banco está preparado.
É normal que `db-init` termine com código `0`; o PostgreSQL continua em execução.
Na primeira vez, as imagens e dependências serão baixadas; não é necessário instalar
Python no computador para preparar o banco.

O arquivo `projeto.env` é criado automaticamente quando não existe. As chaves
`SECRET_KEY` e `FIELD_ENCRYPTION_KEY` são geradas localmente quando faltam; as chaves
existentes são preservadas. Guarde esse arquivo: a chave de criptografia é necessária
para ler as reservas. Ele permanece fora do Git.

Para executar em segundo plano e acompanhar a preparação:

```bash
docker compose up -d
docker compose logs -f db-init
```

| Conexão local | Valor padrão |
|---|---|
| Host | `localhost` |
| Porta | `5432` |
| Banco | `aponte_cafes_dev` |
| Usuário | `aponte_user` |
| Senha | `aponte_password` |

Os usuários fictícios usam a senha `Aponte123!`. O usuário `maria_julia` tem acesso
ao Django Admin. Essas credenciais são para desenvolvimento local.

Para parar os serviços mantendo os dados:

```bash
docker compose down
```

Os dados ficam no volume `postgres_data` e são preservados nas próximas inicializações.
`docker compose down -v` também apaga esse volume e todos os dados do banco.
Para aplicar mudanças nas dependências Python, use `docker compose up --build`.

As variáveis `DBNAME`, `DBUSER`, `DBPASS` e `DBPORT` podem ser personalizadas em um
arquivo `.env` na raiz, lido pelo Compose e pelo Django. Por exemplo, `DBPORT=5433`
libera a porta `5432` para outro banco instalado na máquina. Se já personalizou essas
variáveis em `projeto.env`, use `docker compose --env-file projeto.env up`.
As credenciais do PostgreSQL só são criadas quando o volume está vazio; mudar o arquivo
não altera usuários ou senhas de um banco existente.

### Aplicação Django

Depois da preparação do banco, instale as dependências e inicie a aplicação:

```bash
cd projeto
python -m venv .venv
# Linux/WSL/macOS
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python manage.py runserver
```

No Windows, use `.venv/Scripts/python` no lugar de `.venv/bin/python`.
Acesse `http://127.0.0.1:8000`. Para habilitar a moderação por IA, preencha
`GEMINI_API_KEY` em `projeto.env` com uma chave do
[Google AI Studio](https://aistudio.google.com/apikey).
O arquivo `projeto.env.example` documenta as demais configurações opcionais.

### Erro de conexão com o Docker no WSL

Se aparecer `Cannot connect to the Docker daemon`, verifique o serviço.
Para Docker Engine instalado diretamente no Ubuntu/WSL:

```bash
sudo systemctl start docker
docker info
```

Se o serviço falhar, consulte a causa antes de alterar sua configuração:

```bash
sudo journalctl -u docker.service -n 100 --no-pager
```

Para quem usa Docker Desktop, abra o aplicativo no Windows e habilite a integração
com a distribuição em **Settings → Resources → WSL Integration**.

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
