"""
Verificação de integridade de arquivos enviados (upload) via função hash.

"""
import hashlib


def calcular_sha256_arquivo(arquivo_django):
    """Calcula o SHA-256 de um arquivo do Django (FieldFile ou UploadedFile).
    """
    hasher = hashlib.sha256()
    arquivo_django.seek(0)
    for pedaco in arquivo_django.chunks():
        hasher.update(pedaco)
    arquivo_django.seek(0)
    return hasher.hexdigest()


def verificar_integridade_arquivo(arquivo_django, hash_esperado):
    """Recalcula o SHA-256 do arquivo e compara com o hash esperado.
    Retorna True se o arquivo não foi adulterado (hash bate), False caso
    contrário. Se não houver hash esperado registrado (arquivo enviado antes
    desta verificação existir), retorna None (integridade desconhecida).
    """
    if not hash_esperado:
        return None
    return calcular_sha256_arquivo(arquivo_django) == hash_esperado
