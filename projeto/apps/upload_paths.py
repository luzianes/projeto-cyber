"""
Geração do nome de arquivo salvo no servidor para uploads de imagem.

O nome original enviado pelo usuário nunca é usado para o arquivo em disco
(evita vazar o nome original, colisão entre uploads e qualquer caractere
que escape da sanitização padrão do Django) -- só a extensão é preservada,
e mesmo essa já passou pela validação de conteúdo real da imagem.
"""
import os
import uuid


def _gerar_nome_upload(subpasta, filename):
    extensao = os.path.splitext(filename)[1].lower()
    novo_nome = f'{uuid.uuid4().hex}{extensao}'
    return os.path.join(subpasta, novo_nome)


def upload_profile_image(instance, filename):
    return _gerar_nome_upload('profile_image', filename)


def upload_foto_ambiente(instance, filename):
    return _gerar_nome_upload('fotos_cafeterias', filename)


def upload_foto_avaliacao(instance, filename):
    return _gerar_nome_upload('fotos_experiencias', filename)
