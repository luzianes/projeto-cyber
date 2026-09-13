"""
Campos de modelo com criptografia SIMÉTRICA transparente (proteção em repouso).

--------------------------------------------------------------------------
Por que criptografia SIMÉTRICA (e não assimétrica)?
--------------------------------------------------------------------------
- A própria aplicação precisa TANTO gravar QUANTO ler estes dados em
  operações rotineiras (exibir a reserva para o cliente e para o dono da
  cafeteria). Criptografia assimétrica (RSA/ECC) só se justifica quando quem
  cifra e quem decifra são partes DISTINTAS, ou quando se deseja que o serviço
  apenas cifre e nunca consiga ler. Aqui o mesmo serviço cifra e decifra, então
  a criptografia simétrica autenticada é a escolha correta e mais eficiente.
- RSA, além de mais lento, não é adequado para textos livres (limite de
  tamanho por bloco) e não traria ganho de modelo de ameaça neste caso.

--------------------------------------------------------------------------
Algoritmo
--------------------------------------------------------------------------
Usamos Fernet (biblioteca `cryptography`): AES-128 em modo CBC com IV aleatório
por mensagem + HMAC-SHA256. Isso garante ao mesmo tempo:
  * Confidencialidade  -> o texto em claro não é legível no banco;
  * Integridade/autenticidade -> adulteração do ciphertext é detectada
    (InvalidToken) em vez de decifrar lixo silenciosamente;
  * IV aleatório -> o mesmo texto gera ciphertexts diferentes, evitando
    padrões repetidos.

--------------------------------------------------------------------------
Modelo de ameaça mitigado
--------------------------------------------------------------------------
Vazamento/dump do banco de dados (SQLite local ou PostgreSQL no Azure). Com os
campos cifrados em repouso, um atacante que obtenha o dump do banco NÃO lê os
dados pessoais das reservas sem a chave. A chave (FIELD_ENCRYPTION_KEY) vive
FORA do banco, em variável de ambiente, separando o dado do segredo que o
protege.

Observação: como o Fernet é não determinístico (IV aleatório), estes campos
NÃO devem ser usados em filtros de igualdade (`.filter(campo=...)`) nem em
restrições `unique`. Por isso foram escolhidos campos que só são exibidos,
nunca consultados por valor.
"""
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models


def _get_fernet():
    """Constrói o cifrador a partir da chave em settings/ambiente."""
    key = getattr(settings, 'FIELD_ENCRYPTION_KEY', '') or ''
    if not key:
        raise ImproperlyConfigured(
            "FIELD_ENCRYPTION_KEY não configurada. Gere uma chave com "
            "`python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\"` e defina em projeto.env."
        )
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


class EncryptedFieldMixin:
    """Cifra ao gravar (`get_prep_value`) e decifra ao ler (`from_db_value`).

    Mantém um fallback para dados legados gravados em claro ANTES da migração
    de criptografia: se o valor no banco não for um token Fernet válido,
    devolvemos o próprio valor (assumindo texto legado). Isso evita quebrar
    linhas antigas enquanto elas não são migradas pelo comando
    `encrypt_existing_data`.
    """

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value is None or value == '':
            return value
        token = _get_fernet().encrypt(str(value).encode('utf-8'))
        return token.decode('ascii')

    def from_db_value(self, value, expression, connection):
        if value is None or value == '':
            return value
        try:
            return _get_fernet().decrypt(value.encode('ascii')).decode('utf-8')
        except (InvalidToken, ValueError):
            # Valor legado em claro (ainda não migrado) -> devolve como está.
            return value


class EncryptedCharField(EncryptedFieldMixin, models.TextField):
    """Substitui um CharField cujo conteúdo deve ser cifrado em repouso.

    Herdamos de TextField (coluna sem limite de tamanho) porque o ciphertext
    Fernet é maior que o texto original e estouraria um `max_length` pequeno.
    """


class EncryptedTextField(EncryptedFieldMixin, models.TextField):
    """Substitui um TextField cujo conteúdo deve ser cifrado em repouso."""
