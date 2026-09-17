"""
Mascaramento de dado pessoal exibido em tela para terceiros.

Diferente de criptografia (protege o dado em repouso, contra quem tem acesso
ao banco) e de hash (verifica igualdade/integridade sem guardar o valor),
isto reduz exposição na CAMADA DE APRESENTAÇÃO: uma tela vista/capturada por
alguém que não é o dono do dado (print, compartilhamento de tela, visitante
anônimo navegando) não revela o dado completo, mesmo que a aplicação já o
tenha decifrado para exibição.

Só se aplica onde o dado de UM usuário é mostrado a OUTRA pessoa (ex: nome de
quem avaliou, visível a qualquer visitante da página da cafeteria). Não se
aplica ao próprio dono vendo o próprio dado (perfil, formulário de edição) --
mascarar o próprio e-mail de alguém pra ela mesma não protege nada e só
piora a usabilidade.
"""


def mascarar_nome(nome_completo):
    """"Maria da Silva Sauro" -> "Maria S." (primeiro nome + inicial do
    último sobrenome). Mantém identificável o suficiente pra reconhecer
    quem escreveu a avaliação, sem expor o nome completo na tela."""
    partes = (nome_completo or '').strip().split()
    if len(partes) < 2:
        return nome_completo
    return f'{partes[0]} {partes[-1][0]}.'


def pseudonimizar(valor):
    """Identificador estável e não-reversível para uso em LOG (nunca em
    lugar do dado real armazenado). Mesmo valor -> mesmo pseudônimo -- útil
    pra correlacionar entradas de log do mesmo usuário sem gravar o dado
    pessoal em claro no arquivo de log. Reaproveita o HMAC do blind index
    (`calcular_hash_busca`, chaveado por FIELD_ENCRYPTION_KEY): sem a chave,
    quem só tem acesso ao log não recupera o valor original nem consegue
    forjar/comparar contra um candidato.
    """
    from .crypto_fields import calcular_hash_busca
    if not valor:
        return valor
    return 'usr_' + calcular_hash_busca(valor)[:12]


def mascarar_email(email):
    """"joao.silva@gmail.com" -> "j***a@gmail.com"."""
    if not email or '@' not in email:
        return email
    usuario, dominio = email.split('@', 1)
    if len(usuario) <= 2:
        mascarado = usuario[0] + '*' * max(len(usuario) - 1, 1)
    else:
        mascarado = usuario[0] + '*' * (len(usuario) - 2) + usuario[-1]
    return f'{mascarado}@{dominio}'
