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
dados pessoais sem a chave. A chave (FIELD_ENCRYPTION_KEY) vive FORA do banco,
em variável de ambiente, separando o dado do segredo que o protege.

--------------------------------------------------------------------------
Busca/unicidade em campo cifrado (blind index)
--------------------------------------------------------------------------
Como o Fernet é não determinístico (IV aleatório), o CIPHERTEXT não pode ser
usado em `.filter(campo=...)` nem em restrições `unique` -- o mesmo e-mail
gera um valor cifrado diferente a cada gravação. Para os poucos campos que
precisam disso (email/CNPJ/whatsapp, usados em login e checagem de
duplicidade), mantemos uma coluna adicional "*_hash" com um HMAC-SHA256
determinístico (mesma entrada -> mesmo hash) do valor normalizado, usada só
para lookup/unicidade. A chave do HMAC é a mesma FIELD_ENCRYPTION_KEY: sem
ela, um dump do banco não permite forjar nem comparar hashes, e continua
sendo necessário decifrar para saber o valor real -- o hash não reintroduz o
texto em claro, só permite comparar igualdade.
"""
import hashlib
import hmac
import logging

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models

logger = logging.getLogger('security')


def _get_key_bytes():
    key = getattr(settings, 'FIELD_ENCRYPTION_KEY', '') or ''
    if not key:
        raise ImproperlyConfigured(
            "FIELD_ENCRYPTION_KEY não configurada. Gere uma chave com "
            "`python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\"` e defina em projeto.env."
        )
    return key.encode() if isinstance(key, str) else key


def _get_fernet():
    """Constrói o cifrador a partir da chave em settings/ambiente."""
    return Fernet(_get_key_bytes())


def calcular_hash_busca(valor):
    """HMAC-SHA256 determinístico do valor normalizado (trim + lowercase),
    usado como índice de busca/unicidade para campos cifrados. Normalizar
    antes de gerar o hash é o que permite reproduzir comparação
    case-insensitive (equivalente ao `__iexact` que se usaria num campo em
    claro) mesmo comparando por hash.
    """
    if valor is None:
        return None
    valor_normalizado = str(valor).strip().lower()
    return hmac.new(_get_key_bytes(), valor_normalizado.encode('utf-8'), hashlib.sha256).hexdigest()


class EncryptedFieldMixin:
    """Cifra ao gravar (`get_prep_value`) e decifra ao ler (`from_db_value`).

    Mantém um fallback para dados legados gravados em claro ANTES da migração
    de criptografia: se o valor no banco não for um token Fernet válido,
    devolvemos o próprio valor (assumindo texto legado) -- mas registramos um
    aviso no log de segurança a cada leitura, para que a pendência fique
    visível/monitorável em vez de silenciosa para sempre. Rodar o comando
    `encrypt_existing_data` faz esse aviso parar de aparecer.
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
            logger.warning(
                'Campo cifrado lido em texto puro (legado, ainda nao migrado): '
                'model=%s campo=%s. Rode "manage.py encrypt_existing_data".',
                self.model.__name__ if hasattr(self, 'model') else '?',
                self.name if hasattr(self, 'name') else '?',
            )
            return value


class EncryptedCharField(EncryptedFieldMixin, models.TextField):
    """Substitui um CharField cujo conteúdo deve ser cifrado em repouso.

    Herdamos de TextField (coluna sem limite de tamanho) porque o ciphertext
    Fernet é maior que o texto original e estouraria um `max_length` pequeno.
    """


class EncryptedTextField(EncryptedFieldMixin, models.TextField):
    """Substitui um TextField cujo conteúdo deve ser cifrado em repouso."""
