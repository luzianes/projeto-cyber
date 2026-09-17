"""
Migra para ciphertext os dados que ainda estão em claro no banco.

Quando a criptografia de campo é introduzida em um banco que já tem dados, as
linhas antigas continuam em texto puro. Os campos `EncryptedCharField`/
`EncryptedTextField` sabem LER esse texto legado (fallback, com aviso no log
de segurança a cada leitura), mas ele só passa a ficar cifrado em repouso
depois de ser regravado. Este comando faz exatamente isso, de forma
idempotente, para todos os modelos com campos cifrados: lê cada linha (o
valor volta em claro, seja porque é legado, seja porque foi decifrado) e
regrava (a regravação cifra).

Uso:
    python manage.py encrypt_existing_data          # aplica
    python manage.py encrypt_existing_data --dry-run # só relata

Nota de implementação: para saber se uma linha JÁ está cifrada, precisamos do
valor CRU da coluna (sem passar pelo `from_db_value`, que já decifra/faz
fallback). `.values()`/`.values_list()` do ORM não servem para isso -- eles
também aplicam `from_db_value`. Por isso usamos SQL direto (só leitura) só
para essa checagem.
"""
from django.core.management.base import BaseCommand
from django.db import connection, transaction

from apps.crypto_fields import _get_fernet, calcular_hash_busca
from apps.models import Avaliacao, Cafe, ReservaCafe, UserCliente

# (model, [campos cifrados], [(campo_hash, campo_origem), ...])
MODELOS_CIFRADOS = [
    (UserCliente, ['nome_completo', 'email'], [('email_hash', 'email')]),
    (Cafe, ['responsavel', 'endereco', 'email', 'whatsapp', 'cnpj'],
     [('whatsapp_hash', 'whatsapp'), ('cnpj_hash', 'cnpj')]),
    (Avaliacao, ['comentario', 'valor_gasto'], []),
    (ReservaCafe, ['nome_cliente', 'observacao'], []),
]


def _is_encrypted(raw_value):
    """True se o valor bruto (como está no banco) já for um token Fernet válido."""
    if not raw_value:
        return True  # None/'' não precisam de criptografia
    from cryptography.fernet import InvalidToken
    try:
        _get_fernet().decrypt(raw_value.encode('ascii'))
        return True
    except (InvalidToken, ValueError):
        return False


def _valores_crus(model, campos):
    """Lê id + valor CRU (sem from_db_value) de cada campo, via SQL direto."""
    tabela = model._meta.db_table
    colunas = [model._meta.get_field(campo).column for campo in campos]
    sql = 'SELECT id, {} FROM {}'.format(', '.join(colunas), tabela)
    with connection.cursor() as cursor:
        cursor.execute(sql)
        linhas = cursor.fetchall()
    return {linha[0]: dict(zip(campos, linha[1:])) for linha in linhas}


class Command(BaseCommand):
    help = 'Cifra em repouso os dados ainda gravados em texto puro (todos os modelos com campo cifrado).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Apenas relata quantas linhas seriam migradas, sem gravar.',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']

        for model, campos_cifrados, campos_hash in MODELOS_CIFRADOS:
            self._migrar_modelo(model, campos_cifrados, campos_hash, dry_run)

    def _migrar_modelo(self, model, campos_cifrados, campos_hash, dry_run):
        crus = _valores_crus(model, campos_cifrados)

        pendentes = [
            rid for rid, valores in crus.items()
            if any(not _is_encrypted(v) for v in valores.values())
        ]

        total = len(crus)
        self.stdout.write(
            f'{model.__name__}: {total} | já cifradas: {total - len(pendentes)} | '
            f'a cifrar: {len(pendentes)}'
        )

        if dry_run or not pendentes:
            return

        migradas = 0
        with transaction.atomic():
            for obj in model.objects.filter(id__in=pendentes):
                for campo_hash, campo_origem in campos_hash:
                    setattr(obj, campo_hash, calcular_hash_busca(getattr(obj, campo_origem)))
                obj.save(update_fields=campos_cifrados + [h for h, _ in campos_hash])
                migradas += 1

        self.stdout.write(self.style.SUCCESS(
            f'{model.__name__}: {migradas} linha(s) cifrada(s) em repouso com sucesso.'
        ))
