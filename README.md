# Aponte Cafés - Descobrindo cafeterias

## Descrição

Este é um projeto Django para ajudar os usuários a descobrir e explorar cafeterias no Centro do Recife. O objetivo é fornecer uma plataforma onde os usuários possam visualizar, buscar e avaliar cafeterias próximas, além de poderem adicionar novas cafeterias ao sistema.
Este é um trabalho para a disciplina de Projetos 2 - CESAR School 2024.1.

## Funcionalidades

- Visualizar uma lista de cafeterias no centro da cidade e realizar buscas
- Ver detalhes de cada cafeteria, incluindo localização, horário de funcionamento e telefone para contato
- Adicionar novas cafeterias ao sistema, fornecendo informações básicas como nome, localização e informações de contato
- Cadastrar clientes e editar informações no perfil do usuário
- Favoritar cafeterias, consultar e editar lista de favoritos
- Sistema de reservas de horário para clientes, também com opções de editar e excluir
- Avaliar cafeterias e deixar comentários
- Visualizar histórico de cafeterias visitadas no site

## Tecnologias Utilizadas

- **Framework de Desenvolvimento** - Django - Framework web em Python para o back-end, sem o uso de Django forms nem Generic Views
- **Interface** - HTML/CSS/JavaScript - Para a interface do usuário
- **Banco de dados** - SQLite/PostgreSQL - Para armazenar informações sobre as cafeterias e avaliações dos usuários
- **Hospedagem** - Azure - O produto final será hospedado na plataforma Azure, garantindo confiabilidade e escalabilidade.

## Banco local ficticio (PostgreSQL + Docker no WSL)

O projeto tem um `docker-compose.yml` na raiz com um PostgreSQL local e um `projeto.env` de desenvolvimento ja configurado para usar esse banco.

No WSL, a partir da raiz do repositorio:

```bash
docker compose --env-file projeto.env up -d db
```

Depois rode as migrations e carregue dados ficticios:

```bash
cd projeto
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python manage.py migrate
.venv/bin/python manage.py seed_fake_data --reset
.venv/bin/python manage.py runserver
```

Credenciais do banco local:

```text
host: localhost
porta: 5432
banco: aponte_cafes_dev
usuario: aponte_user
senha: aponte_password
```

Usuarios ficticios da aplicacao usam a senha `Aponte123!`. O usuario `maria_julia` tambem tem acesso ao Django Admin.

## SR1

- As entregas e links relevantes do SR1 estão detalhadas no arquivo [SR1.md](https://github.com/MatheusVelame/projetos2g3/blob/main/SR1.md).

### Histórias

- para o SR1, temos 5 histórias bem definidas e duas implementadas. As 5 histórias são:
  1. Cadastro de Usuários
  2. Cadastro de Cafeterias
  3. Visualizar detalhes das informações das cafeterias cadastradas
  4. Favoritar cafeterias
  5. Avaliar cafeterias cadastradas


## SR2

- As entregas e links relevantes do SR2 estão detalhadas no arquivo [SR2.md](https://github.com/MatheusVelame/projetos2g3/blob/main/SR2.md).

### Histórias

- para o SR2, são 8 histórias bem definidas e duas implementadas. No total:
  1. Visualizar Detalhes de Cafeterias
  2. Fazer e ver Avaliações de Cafeterias
  3. Cadastro de Cafeterias
  4. Cadastro de Usuários
  5. Favoritar/Desfavoritar Cafeterias
  6. Busca por Cafeterias
  7. Consultar lista de favoritos, editar/excluir itens
  8. Sistema de reservas - agendar um horário, consultar lista de reservas e editar/excluir itens
  9. Perfil do usuário - editar/excluir informações
  10. Visualizar histórico de cafeterias visitadas no site


## Licença

Este projeto é licenciado sob a [MIT License](https://opensource.org/licenses/MIT).

## Equipe

- [Arthur Borges](https://github.com/borgearthur)
- [Beatriz Pereira](https://github.com/biapereira2)
- [Lisa Matubara](https://github.com/lilymtbr)
- [Luziane Santos](https://github.com/luzianes)
- [Manuela Cavalcanti](https://github.com/Manuelaamorim)
- [Matheus Velame](https://github.com/MatheusVelame)
- [Matheus Cazé](https://github.com/ogcaze)
- [Thaís Aguiar](https://github.com/aguiarth)
- [Ygor Rosa](https://github.com/YgoRosa)
