# Deploy do Aponte Cafés na Vercel com Supabase

Este roteiro usa **Vercel Hobby** para executar o Django e **Supabase Free** para
PostgreSQL e fotos. O site funciona com seu computador desligado. O Docker
continua sendo uma opção de desenvolvimento local.

**Situação do código:** o projeto ainda precisa das alterações descritas na
etapa 4. Este documento fornece os trechos a aplicar; publicar o código atual
sem esses ajustes não conclui a migração para Vercel/Supabase.

Todos os comandos abaixo são para o **PowerShell do Windows, na raiz do
repositório**, onde ficam `projeto.env` e a pasta `projeto`. Execute um comando
por vez e pare se houver erro. Não há etapa de SSH neste roteiro.

O roteiro cria um **banco novo**. Ele não importa o banco Docker nem as fotos
locais. Para importar dados existentes, preserve a `FIELD_ENCRYPTION_KEY`
correspondente ao banco e transfira também os arquivos, mantendo seus caminhos.

**1. Criar as contas e conferir os planos**

Crie uma conta na [Vercel](https://vercel.com/signup) e outra no
[Supabase](https://supabase.com/dashboard). Selecione **Hobby** na Vercel e uma
organização **Free** no Supabase; evite iniciar testes de planos pagos.

O Hobby é destinado a uso pessoal, não comercial. No Supabase Free, os limites
consultados em setembro de 2026 incluem 500 MB de banco e 1 GB de arquivos;
projetos inativos podem ser pausados após uma semana. Confira os limites e o
estado do projeto antes de uma apresentação. Não é necessário comprar domínio:
use o endereço `NOME_DO_PROJETO.vercel.app`.
[Vercel Hobby](https://vercel.com/docs/plans/hobby) ·
[Supabase Free](https://supabase.com/pricing).

**2. Criar o PostgreSQL no Supabase**

No Supabase, crie um projeto, escolha a região e defina uma senha forte para o
banco. Aguarde a criação terminar. O nome do banco padrão é `postgres`; não crie
manualmente as tabelas Django, pois elas serão criadas por `migrate`.

Em **Connect**, copie os dados de **Session pooler** e **Transaction pooler**:

| Uso | Modo | Porta usual | Usuário usual |
|---|---|---|---|
| Migrações e comandos administrativos no Windows | Session pooler | `5432` | `postgres.PROJECT_REF` |
| Aplicação publicada na Vercel | Transaction pooler | `6543` | `postgres.PROJECT_REF` |

Copie o host completo de cada opção: ele costuma terminar em
`.pooler.supabase.com`, mas não deve ser deduzido apenas pela região. A senha é
a senha do banco definida na criação, e não uma chave de API. Os poolers
compartilhados permitem conexão IPv4 no plano Free; isso evita depender da
conexão direta `db.PROJECT_REF.supabase.co`, que usa IPv6 nesse plano.
Mantenha TLS com `DBSSLMODE=require`.
[Conexões do Supabase](https://supabase.com/docs/guides/database/connecting-to-postgres).

Este projeto acessa PostgreSQL pelo Django e mantém seu próprio login. Não é
necessário migrar usuários para Supabase Auth. Na configuração **Data API** do
Supabase, desative **Enable Data API** antes de criar as tabelas. Assim, as
tabelas de usuários e reservas não ficam disponíveis pela API REST automática.
O acesso PostgreSQL e o serviço de Storage usados aqui são separados dessa API.
[Configuração da Data API](https://supabase.com/docs/guides/api/securing-your-api#disable-the-data-api).

**3. Preparar o armazenamento das fotos**

Em **Storage**, crie um bucket chamado `media`, marcado como **Public**. Ele
receberá as fotos de cafeterias, perfis e avaliações que o site exibe publicamente;
qualquer pessoa com a URL poderá visualizá-las. Não envie backups ou segredos
para esse bucket. Ser público para leitura não libera uploads anônimos.
[Buckets públicos](https://supabase.com/docs/guides/storage/buckets/fundamentals).

Nas configurações **S3** do Storage, gere **Access Key ID** e **Secret Access Key**.
Guarde também **Endpoint** e **Region** exatamente como aparecem no painel.
Essas credenciais S3 são diferentes das chaves `anon`, `publishable` e
`service_role`. Elas ficam somente no servidor; não crie uma política de escrita
anônima para fazer o upload funcionar.
[Credenciais S3](https://supabase.com/docs/guides/storage/s3/authentication).

Para a demonstração, use fotos de até **3 MB**, uma por envio. As requisições que
passam por uma função Vercel têm limite de 4,5 MB, incluindo o restante do
formulário. Fotos maiores exigem outra implementação de upload direto ao Storage.
[Limite de upload da Vercel](https://vercel.com/docs/errors/function_payload_too_large).

**4. Adaptar o projeto localmente antes de publicar**

Faça estas alterações nos arquivos indicados. Não basta cadastrar as novas
variáveis no painel: o código atual ainda não conhece a configuração S3.

**4.1. Preparar Python e atualizar as dependências**

Instale Python **3.12** no Windows, caso ainda não esteja disponível. Confira:

```powershell
py -3.12 --version
```

Acrescente à `.gitignore` da raiz estas linhas antes de criar o ambiente e o
arquivo de segredos:

```gitignore
.venv-deploy/
projeto.env.deploy
.vercel/
.env.local
```

Crie um ambiente novo, exclusivo para validar o deploy. Se `.venv-deploy` já
existir, confirme que usa Python 3.12 e não contém dependências de outro projeto:

```powershell
py -3.12 -m venv .venv-deploy
.\.venv-deploy\Scripts\python.exe -m pip install --upgrade pip
.\.venv-deploy\Scripts\python.exe -m pip install "Django>=5.2,<5.3" "django-storages[s3]>=1.14,<2" cryptography Pillow psycopg2-binary python-dotenv whitenoise requests gunicorn colorama
.\.venv-deploy\Scripts\python.exe -m pip check
```

O `requirements.txt` atual fixa Django 5.0.3, cuja série perdeu suporte em abril
de 2025. O comando acima seleciona a série 5.2 LTS e instala as dependências
necessárias ao projeto e ao Storage. Registre as versões resolvidas, incluindo
dependências transitivas, em `projeto/requirements.txt`:

```powershell
.\.venv-deploy\Scripts\python.exe -c "from pathlib import Path; import subprocess, sys; Path('projeto/requirements.txt').write_text(subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'], text=True), encoding='utf-8')"
```

Esse comando substitui o arquivo de dependências; revise a alteração no Git.
Use esse mesmo arquivo no desenvolvimento e no deploy e execute a validação da
etapa 6 antes de publicar. O uso de `write_text` evita gerar UTF-16 com o
redirecionamento de saída do Windows PowerShell.
[Suporte do Django](https://www.djangoproject.com/download/#supported-versions).

**4.2. Selecionar o arquivo de ambiente sem alterar seu ambiente local**

Em `projeto/g3/settings.py`, substitua as duas chamadas iniciais de `load_dotenv`
por este bloco, logo depois da definição de `BASE_DIR`:

```python
deploy_env_file = os.getenv('DJANGO_ENV_FILE')
if deploy_env_file:
    load_dotenv(deploy_env_file)
elif not os.getenv('VERCEL'):
    load_dotenv(BASE_DIR.parent / '.env')
    load_dotenv(BASE_DIR.parent / 'projeto.env')
```

No Windows, `DJANGO_ENV_FILE` selecionará `projeto.env.deploy`. Na Vercel, as
variáveis virão do painel. O `projeto.env` usado pelo Docker permanece local.
Variáveis já definidas no processo têm precedência sobre os arquivos.

**4.3. Preparar a conexão com o pooler**

Em `settings.py`, logo **depois de todo o bloco `if NOT_PROD: ... else: ...`** que
define o banco, acrescente, sem indentação inicial:

```python
if not NOT_PROD:
    DATABASES['default']['CONN_MAX_AGE'] = 0
    DATABASES['default']['DISABLE_SERVER_SIDE_CURSORS'] = True
```

Continue usando `psycopg2-binary`, instalado acima. Não habilite prepared
statements no modo Transaction. A opção de cursores evita incompatibilidades
com conexões compartilhadas; as migrações usarão o Session pooler.
[Django e transaction pooling](https://docs.djangoproject.com/en/5.2/ref/databases/#transaction-pooling-and-server-side-cursors).

**4.4. Configurar os arquivos estáticos e as fotos**

Em `settings.py`, remova a linha `STATICFILES_STORAGE = ...` e coloque o bloco
abaixo em seu lugar. Mantenha `STATIC_URL`, `STATIC_ROOT`, `MEDIA_URL` e
`MEDIA_ROOT` existentes:

```python
USE_SUPABASE_STORAGE = env_bool('USE_SUPABASE_STORAGE')

STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage',
    },
}

if USE_SUPABASE_STORAGE:
    STORAGES['default'] = {
        'BACKEND': 'storages.backends.s3.S3Storage',
        'OPTIONS': {
            'access_key': env_required('SUPABASE_S3_ACCESS_KEY_ID'),
            'secret_key': env_required('SUPABASE_S3_SECRET_ACCESS_KEY'),
            'bucket_name': env_required('SUPABASE_STORAGE_BUCKET'),
            'endpoint_url': env_required('SUPABASE_S3_ENDPOINT_URL'),
            'region_name': env_required('SUPABASE_S3_REGION_NAME'),
            'addressing_style': 'path',
            'signature_version': 's3v4',
            'default_acl': None,
            'file_overwrite': False,
            'querystring_auth': False,
            'custom_domain': env_required('SUPABASE_MEDIA_DOMAIN'),
            'url_protocol': 'https:',
        },
    }
```

`default` armazena as fotos no Supabase; `staticfiles` prepara CSS, JavaScript e
imagens do próprio projeto. O caminho público das fotos virá de
`SUPABASE_MEDIA_DOMAIN`, descrito na etapa 5. Os templates já usam propriedades
como `cafe.foto_ambiente.url`. Não use `default_acl='public-read'`: a visibilidade
é configurada no bucket Supabase, que não implementa ACLs S3 dessa forma.
[Configuração do django-storages](https://django-storages.readthedocs.io/en/latest/backends/amazon-S3.html) ·
[Compatibilidade S3 do Supabase](https://supabase.com/docs/guides/storage/s3/compatibility).

**4.5. Enviar logs para a saída da aplicação**

Em `settings.py`, substitua **todo** o trecho que começa em `LOG_DIR = ...` e
termina no dicionário `LOGGING` por este bloco. Não deixe `LOG_DIR.mkdir(...)`
ou o `FileHandler` antigo ativos:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'security': {'format': '%(asctime)s [%(levelname)s] %(message)s'},
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'security',
        },
    },
    'loggers': {
        'security': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
```

Os eventos aparecerão nos logs da Vercel. Gravar permanentemente em
`projeto/logs/security.log` não é apropriado para esse deploy.

**4.6. Servir `/media/` localmente apenas em desenvolvimento**

Substitua o conteúdo de `projeto/g3/urls.py` por:

```python
from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.urls')),
    path('apps/', include(('apps.urls', 'apps'), namespace='projeto/apps')),
]

if settings.DEBUG and not settings.USE_SUPABASE_STORAGE:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

Em produção, as fotos serão carregadas pelas URLs do Supabase, sem mapeamento
de pasta `/media/` na Vercel.

**4.7. Fixar a versão Python da Vercel**

Crie `projeto/.python-version` contendo uma única linha:

```text
3.12
```

Como a `.gitignore` atual ignora `.python-version`, acrescente **ao final dela**:

```gitignore
!projeto/.python-version
```

A configuração do projeto Vercel terá `projeto` como diretório raiz. A Vercel
detectará `manage.py` e `g3.wsgi.application`, já definido em `settings.py`.
[Versão Python na Vercel](https://vercel.com/docs/functions/runtimes/python/python-version).

**5. Preparar as variáveis de produção no Windows**

Na raiz do repositório, crie `projeto.env.deploy` pelo editor. **Não sobrescreva
seu `projeto.env` atual.** Para banco novo, copie este conteúdo e substitua os
marcadores. Escolha um nome para o projeto Vercel, por exemplo
`aponte-cafes-seunome`, e use seu domínio previsto em `ALLOWED_HOSTS` e
`CSRF_TRUSTED_ORIGINS`; a etapa 8 confirma o endereço atribuído.

```dotenv
TARGET_ENV=prod
DEBUG=0
SECRET_KEY=
FIELD_ENCRYPTION_KEY=
ALLOWED_HOSTS=NOME_DO_PROJETO.vercel.app
CSRF_TRUSTED_ORIGINS=https://NOME_DO_PROJETO.vercel.app
SECURE_SSL_REDIRECT=1
SECURE_HSTS_SECONDS=31536000

# Session pooler: usado pelos comandos administrativos no Windows.
DBHOST=HOST_DO_SESSION_POOLER
DBPORT=5432
DBNAME=postgres
DBUSER=postgres.PROJECT_REF
DBPASS='SENHA_DO_BANCO'
DBSSLMODE=require

USE_SUPABASE_STORAGE=1
SUPABASE_STORAGE_BUCKET=media
SUPABASE_S3_ACCESS_KEY_ID=ACCESS_KEY_ID_DO_STORAGE
SUPABASE_S3_SECRET_ACCESS_KEY=SECRET_ACCESS_KEY_DO_STORAGE
SUPABASE_S3_ENDPOINT_URL=ENDPOINT_S3_COPIADO_DO_PAINEL
SUPABASE_S3_REGION_NAME=REGIAO_COPIADA_DO_PAINEL
SUPABASE_MEDIA_DOMAIN=PROJECT_REF.supabase.co/storage/v1/object/public/media

RECAPTCHA_SITE_KEY=CHAVE_PUBLICA_RECAPTCHA_V2
RECAPTCHA_SECRET_KEY=CHAVE_SECRETA_RECAPTCHA_V2
GEMINI_API_KEY=

EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
EMAIL_USE_TLS=0
EMAIL_USE_SSL=0
DEFAULT_FROM_EMAIL=no-reply@apontecafes.local
SERVER_EMAIL=no-reply@apontecafes.local
```

`SUPABASE_MEDIA_DOMAIN` não leva `https://` nem barra final; inclui o caminho
`/storage/v1/object/public/media`. Já `SUPABASE_S3_ENDPOINT_URL` inclui `https://`
e termina em `/storage/v1/s3`: copie do painel, pois pode usar o host
`PROJECT_REF.storage.supabase.co`. Esses dois endereços têm funções diferentes.

No [painel do reCAPTCHA](https://www.google.com/recaptcha/admin/create), crie uma
chave **v2 — caixa de seleção "Não sou um robô"**, autorize apenas seu domínio
`NOME_DO_PROJETO.vercel.app` e preencha as duas variáveis. As chaves de teste
padrão do código sempre aprovam verificações e não devem ser usadas no site
público. Se o domínio atribuído for diferente, atualize-o no painel do Google.
[Orientações do reCAPTCHA](https://developers.google.com/recaptcha/docs/faq).

Deixe `GEMINI_API_KEY` vazio se não usar IA. Em um banco novo, gere as duas chaves
vazias com este comando, que preserva valores já existentes:

```powershell
@'
from pathlib import Path
from secrets import token_urlsafe
from cryptography.fernet import Fernet
from dotenv import dotenv_values, set_key

path = Path('projeto.env.deploy')
if not path.is_file():
    raise SystemExit('Crie projeto.env.deploy antes de gerar as chaves.')
values = dotenv_values(path)
for key, generate in {
    'SECRET_KEY': lambda: token_urlsafe(64),
    'FIELD_ENCRYPTION_KEY': lambda: Fernet.generate_key().decode(),
}.items():
    if not values.get(key):
        set_key(path, key, generate())
print('Chaves configuradas; valores existentes preservados.')
'@ | .\.venv-deploy\Scripts\python.exe -
```

Não compartilhe esse arquivo nem envie seus valores para o GitHub. Guarde uma
cópia privada junto ao backup do banco. Se importar reservas existentes, use a
`FIELD_ENCRYPTION_KEY` original em vez de gerar outra. Nos arquivos dotenv,
coloque senhas entre aspas simples; escape uma aspa simples interna como `\'`.

Confirme que o Git ignora os segredos e o ambiente:

```powershell
git check-ignore projeto.env projeto.env.deploy .venv-deploy/pyvenv.cfg
```

**6. Validar localmente e preparar o banco remoto**

Use um PowerShell novo na raiz do projeto e selecione o arquivo de produção:

```powershell
$env:DJANGO_ENV_FILE = (Resolve-Path -LiteralPath projeto.env.deploy).Path
```

Primeiro execute os testes em um banco SQLite de teste, com armazenamento local.
O bloco restaura as opções ao terminar; não execute os testes usando o banco
de produção do Supabase:

```powershell
try {
    $env:TARGET_ENV = 'dev'
    $env:USE_POSTGRES = '0'
    $env:USE_SUPABASE_STORAGE = '0'
    $env:DEBUG = '1'
    $env:SECURE_SSL_REDIRECT = '0'
    .\.venv-deploy\Scripts\python.exe projeto/manage.py test apps
    if ($LASTEXITCODE -ne 0) { throw 'Corrija os testes antes de continuar.' }
}
finally {
    foreach ($deployFlag in @('TARGET_ENV', 'USE_POSTGRES', 'USE_SUPABASE_STORAGE', 'DEBUG', 'SECURE_SSL_REDIRECT')) {
        Remove-Item -LiteralPath "Env:$deployFlag" -ErrorAction SilentlyContinue
    }
}
```

Depois, usando os valores de produção do arquivo e o **Session pooler**, confira
o destino sem imprimir senhas e aplique as migrações:

```powershell
.\.venv-deploy\Scripts\python.exe projeto/manage.py shell -c "from django.conf import settings; d=settings.DATABASES['default']; print(settings.TARGET_ENV, d['HOST'], d['PORT'], d['NAME'])"
.\.venv-deploy\Scripts\python.exe projeto/manage.py check --deploy --fail-level WARNING
.\.venv-deploy\Scripts\python.exe projeto/manage.py migrate
.\.venv-deploy\Scripts\python.exe projeto/manage.py collectstatic --noinput
```

O destino deve ser seu Supabase, com `prod`, porta `5432` e banco `postgres`.
Se quiser começar com exemplos, execute os dois comandos abaixo **antes de criar
seu administrador e antes de publicar**:

```powershell
.\.venv-deploy\Scripts\python.exe projeto/manage.py seed_fake_data --if-empty
.\.venv-deploy\Scripts\python.exe projeto/manage.py shell -c "from django.contrib.auth.models import User; from apps.management.commands.seed_fake_data import USERS; User.objects.filter(username__in=[u['username'] for u in USERS]).update(is_active=False)"
```

O segundo comando desativa as contas fictícias, cujas senhas são públicas.
Os dados de cafeterias, reservas e avaliações permanecem. Pule ambos para
começar vazio. Não use `--reset` em um banco com dados a preservar.

Crie um administrador próprio, com nome diferente dos exemplos, como `admin_cyber`:

```powershell
.\.venv-deploy\Scripts\python.exe projeto/manage.py createsuperuser
```

**7. Enviar os arquivos preparados ao GitHub**

Revise e faça commit dos ajustes de código, `projeto/requirements.txt`,
`projeto/.python-version`, `.gitignore` e documentação. Envie para a branch que
será usada na Vercel. O repositório configurado atualmente é
`https://github.com/luzianes/projeto-cyber.git`; use um fork se necessário.

Não inclua `projeto.env`, `projeto.env.deploy`, ambientes virtuais, uploads ou
`staticfiles`. A Vercel instalará as dependências e construirá seus estáticos.

**8. Importar na Vercel e configurar o ambiente**

Na Vercel, use **Add New > Project > Import Git Repository**. Autorize o
repositório no GitHub e configure:

| Campo | Valor |
|---|---|
| Plano / escopo | Sua conta Hobby |
| Project Name | O nome escolhido na etapa 5 |
| Framework Preset | `Django` |
| Root Directory | `projeto` |
| Install Command | `python -m pip install -r requirements.txt` |
| Build Command | `python manage.py check --deploy --fail-level WARNING` |
| Output Directory | Padrão do preset, sem sobrescrever |

O preset Django usa o WSGI existente e executa `collectstatic` automaticamente.
Não configure `runserver`, porta própria ou um diretório de saída de aplicação
JavaScript. Não coloque `migrate`, `seed_fake_data` ou `createsuperuser` no build:
eles já foram executados de forma controlada na etapa 6.
[Django na Vercel](https://vercel.com/docs/frameworks/full-stack/django) ·
[Configurações do projeto](https://vercel.com/docs/project-configuration/project-settings).

Antes de clicar em **Deploy**, cadastre as variáveis da etapa 5 em
**Environment Variables**, selecionando **Production**, com estes ajustes:

| Variável | Valor na Vercel |
|---|---|
| `DBHOST` | Host exato de **Transaction pooler** no Supabase |
| `DBPORT` | `6543`, ou a porta exibida para esse modo no painel |
| `DBNAME`, `DBUSER`, `DBPASS`, `DBSSLMODE` | Valores correspondentes à conexão Transaction; TLS `require` |
| `ALLOWED_HOSTS` | Domínio do projeto, sem `https://` |
| `CSRF_TRUSTED_ORIGINS` | `https://` seguido do mesmo domínio, sem barra final |
| Demais variáveis | Mesmos valores de produção do arquivo local |

No painel, insira valores **sem as aspas delimitadoras do dotenv**. Por exemplo,
`DBPASS='senha'` no arquivo corresponde ao valor `senha` no painel, sem as aspas.
Copie exatamente as mesmas `SECRET_KEY` e `FIELD_ENCRYPTION_KEY`. Não cadastre
`DJANGO_ENV_FILE`: o caminho do Windows não existe na Vercel. Não envie o arquivo
de segredos para a plataforma como parte do repositório.

O projeto usa `DBHOST`, `DBPORT`, `DBNAME`, `DBUSER` e `DBPASS`; cadastrar apenas
`DATABASE_URL` não configura o banco neste código. Não habilite automaticamente
as credenciais de produção para **Preview**: uma branch de teste não deve alterar
seu banco de produção. Previews completos exigem banco e credenciais separados.
[Variáveis por ambiente](https://vercel.com/docs/environment-variables).

Clique em **Deploy**. Confira a **Production Branch** e o domínio em
**Settings > Domains**. Se o endereço for diferente do previsto, atualize
`ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, o reCAPTCHA e seu arquivo local, e faça
**Redeploy** para aplicar as variáveis. Para vários domínios, separe os valores
por espaços; não use `*` nem libere todo `.vercel.app`.

**9. Testar o site publicado e a persistência das fotos**

Abra o domínio de produção, não uma URL temporária de preview. Verifique:

- Página inicial, cafeterias, CSS e imagens do projeto.
- `/admin/`, usando seu administrador próprio.
- Cadastro e login pela aplicação, com o reCAPTCHA real.
- Uma reserva e a leitura posterior dos seus dados.
- Uma foto de perfil ou cafeteria menor que 3 MB.

Confirme no Supabase Storage que a foto apareceu no bucket `media`. A URL exibida
pelo site deve apontar para `/storage/v1/object/public/media/` no Supabase.
Faça um **Redeploy** e confirme que a mesma foto e os dados continuam disponíveis.
Fotos existentes apenas em seu Windows não aparecerão automaticamente.

Se a conexão funcionar no Windows, mas falhar na Vercel, compare host, porta e
usuário do **Transaction pooler**, e confira `DBSSLMODE=require`.

**10. Configurar IA e recuperação de senha, se necessário**

Para moderação por IA, configure `GEMINI_API_KEY` no ambiente **Production**.
Sem ela, novas avaliações ficam pendentes. A franquia e a cobrança da API são
separadas da hospedagem; verifique a configuração da sua conta no provedor.

O backend de e-mail inicial escreve nos logs e **não entrega mensagens**.
Supabase Auth não envia a recuperação de senha deste login Django. Para entregar
os e-mails, configure um provedor SMTP com remetente autorizado, por exemplo:

```dotenv
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=HOST_SMTP
EMAIL_PORT=587
EMAIL_USE_TLS=1
EMAIL_USE_SSL=0
EMAIL_HOST_USER=USUARIO_SMTP
EMAIL_HOST_PASSWORD='CREDENCIAL_SMTP'
DEFAULT_FROM_EMAIL=REMETENTE_AUTORIZADO
SERVER_EMAIL=REMETENTE_AUTORIZADO
```

Para TLS implícito/465, use `EMAIL_PORT=465`, `EMAIL_USE_TLS=0` e
`EMAIL_USE_SSL=1`. Cadastre os valores no painel sem aspas delimitadoras,
faça **Redeploy** e teste o fluxo completo com uma conta válida.

**11. Atualizar depois sem perder dados**

Preserve as duas chaves da aplicação, as credenciais e o bucket. Faça backups do
banco e das fotos antes de alterar estruturas; o plano Free não inclui os
backups automáticos de banco oferecidos nos planos pagos.
[Recursos dos planos Supabase](https://supabase.com/pricing).

Valide as alterações localmente como na etapa 6. Se houver migrações, revise-as
e aplique as compatíveis com o site atual usando **Session pooler**, antes de
enviar a nova versão para a branch de produção. Migrações destrutivas ou
incompatíveis exigem uma janela de manutenção e um plano de restauração.

Depois faça commit e push para a **Production Branch** configurada. A integração
com GitHub inicia um novo deploy. Mudanças apenas nas variáveis do painel exigem
**Redeploy**. Não gere novas chaves nem repita o seed em cada atualização.

**12. Diagnosticar problemas**

Na Vercel, consulte os **Build Logs** para falhas de instalação/coleta de estáticos
e os **Runtime Logs** para erros ao acessar o site. No Supabase, confira se o
projeto está ativo, o pooler e os logs de banco/Storage.

| Sintoma | O que conferir |
|---|---|
| Django não detectado / `No module named g3` | Root Directory `projeto`, preset Django e `manage.py` no diretório selecionado. |
| Build usa Python inesperado | `projeto/.python-version` deve estar no Git e conter `3.12`. |
| `Read-only file system` / falha no handler `security_file` | Remova o bloco de logs em arquivo conforme 4.5; fotos devem usar S3. |
| `Network is unreachable` ao conectar ao banco | Use o host do pooler compartilhado, compatível com IPv4, e não o host direto IPv6. |
| Erro de autenticação / `Tenant or user not found` | Confira host, modo e usuário completo `postgres.PROJECT_REF`; a senha é a do banco. |
| `relation ... does not exist` | Execute `migrate` no Supabase correto pela etapa 6. |
| Cursor inexistente no PostgreSQL | Aplique `DISABLE_SERVER_SIDE_CURSORS=True` em produção. |
| `InvalidAccessKeyId` / `SignatureDoesNotMatch` no upload | Confira as chaves S3, endpoint e região; não use chaves `anon`/`service_role` nesses campos. |
| Upload funciona, mas a foto não abre | Bucket público, objeto existente e `SUPABASE_MEDIA_DOMAIN` com o caminho público correto. |
| Foto desaparece após deploy | Confirme `USE_SUPABASE_STORAGE=1` e o backend S3; armazenamento local não é persistência de uploads. |
| `413 FUNCTION_PAYLOAD_TOO_LARGE` | Reduza a foto; use até 3 MB por envio neste fluxo. |
| `DisallowedHost` / 400 | Cadastre o domínio de produção exato, sem protocolo, e faça Redeploy. |
| CSRF / 403 em formulário | Origem HTTPS exata em `CSRF_TRUSTED_ORIGINS`, cookies HTTPS e Redeploy. |
| reCAPTCHA com domínio/chave inválidos | Chaves v2 reais e domínio autorizado no Google. |
| `Missing staticfiles manifest entry` | Verifique arquivo e maiúsculas/minúsculas em `apps/static`; execute `collectstatic` e publique a correção. |
| Alterações nas variáveis sem efeito | Faça Redeploy; o deploy existente conserva a configuração anterior. |

Mantenha `DEBUG=0` no site público. Ao compartilhar logs, remova credenciais,
tokens, dados pessoais e links de recuperação de senha.
