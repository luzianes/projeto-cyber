"""
Verificação de integridade de arquivos enviados (upload) via função hash.

--------------------------------------------------------------------------
Por que hash (integridade) e não cifra (confidencialidade) nos arquivos?
--------------------------------------------------------------------------
SHA-256 aqui resolve um problema DIFERENTE do que a criptografia em
crypto_fields.py resolve: detectar se o arquivo em disco foi adulterado
depois do upload (comparando o hash salvo no banco com o hash recalculado),
não escondê-lo de quem tem acesso ao disco.

Os três ImageField do projeto (profile_image, foto_ambiente, foto_avaliacao)
foram DELIBERADAMENTE deixados sem cifra em repouso, por escolha, não por
omissão:
  * foto_ambiente e foto_avaliacao são exibidas PUBLICAMENTE (qualquer
    visitante vê a foto da cafeteria/da avaliação na página de detalhes).
    Cifrar em repouso não reduz exposição real nenhuma -- o dado já é
    público por design; seria apenas custo extra sem ganho de segurança.
  * profile_image é mais privada (só aparece no perfil do próprio usuário),
    mas cifrar um ARQUIVO exigiria trocar o serving direto (Whitenoise/
    static, com cache e URL estável) por uma view própria que decifra a
    cada request -- perde cache de navegador/CDN e complica a entrega, só
    para um dado que a própria aplicação já mostra na tela do usuário
    autenticado. Não foi considerado custo/benefício favorável para este
    projeto; a mitigação escolhida para upload malicioso/adulterado foi
    validação de conteúdo (validators.py) + este hash de integridade, não
    confidencialidade do arquivo.
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
