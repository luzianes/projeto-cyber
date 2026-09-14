"""
Confere se os arquivos enviados por upload (fotos de cafeteria, de avaliação,
de perfil) ainda batem com o SHA-256 calculado no momento do envio.

"""
from django.core.management.base import BaseCommand
import logging

from apps.integrity import verificar_integridade_arquivo
from apps.models import Avaliacao, Cafe, UserCliente

logger = logging.getLogger('security')

CAMPOS_COM_HASH = [
    (Cafe, 'foto_ambiente', 'foto_ambiente_sha256'),
    (Avaliacao, 'foto_avaliacao', 'foto_avaliacao_sha256'),
    (UserCliente, 'profile_image', 'profile_image_sha256'),
]


class Command(BaseCommand):
    help = 'Verifica a integridade (SHA-256) dos arquivos enviados por upload.'

    def handle(self, *args, **options):
        ok = adulterados = sem_hash = sem_arquivo = 0

        for modelo, campo_arquivo, campo_hash in CAMPOS_COM_HASH:
            for obj in modelo.objects.exclude(**{f'{campo_arquivo}': ''}).exclude(**{f'{campo_arquivo}__isnull': True}):
                arquivo = getattr(obj, campo_arquivo)
                hash_esperado = getattr(obj, campo_hash)

                try:
                    resultado = verificar_integridade_arquivo(arquivo, hash_esperado)
                except FileNotFoundError:
                    sem_arquivo += 1
                    self.stdout.write(self.style.WARNING(
                        f'{modelo.__name__}#{obj.pk}.{campo_arquivo}: arquivo ausente em disco'
                    ))
                    continue

                if resultado is None:
                    sem_hash += 1
                elif resultado is True:
                    ok += 1
                else:
                    adulterados += 1
                    logger.warning(
                        'Integridade violada: %s#%s.%s nao bate com o hash registrado no upload',
                        modelo.__name__, obj.pk, campo_arquivo,
                    )

        self.stdout.write(
            f'OK: {ok} | adulterados: {adulterados} | sem hash registrado: {sem_hash} | '
            f'sem arquivo em disco: {sem_arquivo}'
        )
