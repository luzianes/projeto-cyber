"""
Validação de conteúdo de arquivos de imagem enviados (upload).
"""
from django.core.exceptions import ValidationError
from PIL import Image, UnidentifiedImageError


def validar_conteudo_imagem(arquivo):
    """Garante que o arquivo enviado é uma imagem de verdade, não apenas um
    arquivo com extensão de imagem (ex: um shell.php renomeado para .jpg).
    """
    posicao = arquivo.tell()
    try:
        Image.open(arquivo).verify()
    except (UnidentifiedImageError, OSError):
        raise ValidationError('O arquivo enviado não é uma imagem válida.')
    finally:
        arquivo.seek(posicao)
