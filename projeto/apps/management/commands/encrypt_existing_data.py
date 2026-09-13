"""
Migra para ciphertext os dados de reservas que ainda estão em claro no banco.

Quando a criptografia de campo é introduzida em um banco que já tem dados, as
linhas antigas continuam em texto puro. Os campos `EncryptedCharField`/
`EncryptedTextField` sabem LER esse texto legado (fallback), mas ele só passa a
ficar cifrado em repouso depois de ser regravado. Este comando faz exatamente
isso, de forma idempotente: lê cada reserva (o valor volta em claro, seja
porque é legado, seja porque foi decifrado) e regrava (a regravação cifra).

Uso:
    python manage.py encrypt_existing_data          # aplica
    python manage.py encrypt_existing_data --dry-run # só relata
"""
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.crypto_fields import _get_fernet
from apps.models import ReservaCafe


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


class Command(BaseCommand):
    help = 'Cifra em repouso os dados de reservas ainda gravados em texto puro.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Apenas relata quantas linhas seriam migradas, sem gravar.',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']

        # Lê os valores CRUS (sem passar pela decifragem) direto do banco para
        # saber quais linhas ainda estão em claro.
        crus = {
            row['id']: row
            for row in ReservaCafe.objects.values(
                'id', 'nome_cliente', 'observacao'
            )
        }

        pendentes = []
        for rid, row in crus.items():
            if not _is_encrypted(row['nome_cliente']) or \
               not _is_encrypted(row['observacao']):
                pendentes.append(rid)

        total = ReservaCafe.objects.count()
        self.stdout.write(
            f'Reservas: {total} | já cifradas: {total - len(pendentes)} | '
            f'a cifrar: {len(pendentes)}'
        )

        if dry_run or not pendentes:
            self.stdout.write(self.style.SUCCESS('Nada a fazer.' if not pendentes
                                                 else 'Dry-run: nada gravado.'))
            return

        migradas = 0
        with transaction.atomic():
            for reserva in ReservaCafe.objects.filter(id__in=pendentes):
                # Ao ler, o campo devolve o texto em claro (legado ou decifrado);
                # ao salvar, o campo cifra automaticamente.
                reserva.save(update_fields=['nome_cliente', 'observacao'])
                migradas += 1

        self.stdout.write(self.style.SUCCESS(
            f'{migradas} reserva(s) cifrada(s) em repouso com sucesso.'
        ))
