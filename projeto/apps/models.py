from django.core.validators import EmailValidator
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.db.models import Avg
from datetime import datetime

from .crypto_fields import EncryptedCharField, EncryptedTextField, calcular_hash_busca
from .integrity import calcular_sha256_arquivo
from .masking import mascarar_nome
from .validators import validar_conteudo_imagem
from .upload_paths import upload_profile_image, upload_foto_ambiente, upload_foto_avaliacao
from .mensageria_cripto import cifrar, decifrar

class UserCliente(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    # Cifrados em repouso (dados pessoais). "password"/"confirm_password" que
    # existiam aqui foram removidos: senha real vive só em django.contrib.auth
    # User (hash), nunca em texto puro num campo próprio.
    nome_completo = EncryptedCharField(default="Desconhecido")
    email = EncryptedCharField(validators=[EmailValidator()])
    # Hash determinístico (HMAC) do e-mail normalizado, só para lookup/
    # unicidade -- o e-mail cifrado (Fernet) não serve pra isso. Ver
    # crypto_fields.py.
    email_hash = models.CharField(max_length=64, unique=True, editable=False, blank=True)
    is_business = models.BooleanField(default=False)
    profile_image = models.ImageField(upload_to=upload_profile_image, blank=True, null=True, validators=[validar_conteudo_imagem])
    # SHA-256 do profile_image calculado no upload, para verificar depois se o arquivo em disco foi adulterado.
    profile_image_sha256 = models.CharField(max_length=64, blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.email:
            self.email_hash = calcular_hash_busca(self.email)
        if self.profile_image and not self.profile_image._committed:
            self.profile_image_sha256 = calcular_sha256_arquivo(self.profile_image.file)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email

    def nome_exibicao_publico(self):
        """Nome mascarado, para exibir a OUTRAS pessoas (ex: autor de uma
        avaliação, visível a qualquer visitante). Ver apps/masking.py."""
        return mascarar_nome(self.nome_completo)

class Cafe(models.Model):
    # Cifrados em repouso (dados pessoais/comerciais). cnpj/whatsapp mantêm
    # colunas "*_hash" (HMAC determinístico) para lookup/unicidade -- ver
    # crypto_fields.py.
    responsavel = EncryptedCharField(default='Nome do responsável não informado')
    nome_cafeteria = models.CharField(max_length=100, blank=False, default='Nome não informado')
    endereco = EncryptedCharField(default='Endereço não informado')
    descricao = models.TextField(blank=False, default='Descrição não informada')
    email = EncryptedCharField(validators=[EmailValidator()])
    whatsapp = EncryptedCharField(default='5500000000000')
    whatsapp_hash = models.CharField(max_length=64, unique=True, editable=False, blank=True)
    horas_funcionamento = models.CharField(max_length=100, blank=False, default='Horário não informado')
    link_redesocial = models.URLField(max_length=200, blank=True)
    foto_ambiente = models.ImageField(upload_to=upload_foto_ambiente, blank=True, null=True, validators=[validar_conteudo_imagem])
    # SHA-256 do foto_ambiente calculado no upload, para verificar depois se o arquivo em disco foi adulterado.
    foto_ambiente_sha256 = models.CharField(max_length=64, blank=True, null=True)
    cnpj = EncryptedCharField(default='00000000000000')
    cnpj_hash = models.CharField(max_length=64, unique=True, editable=False, blank=True)
    site_cafeteria = models.URLField(max_length=200, blank=True)
    empresario = models.ForeignKey(UserCliente, on_delete=models.CASCADE, related_name='cafeterias', null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.cnpj:
            self.cnpj_hash = calcular_hash_busca(self.cnpj)
        if self.whatsapp:
            self.whatsapp_hash = calcular_hash_busca(self.whatsapp)
        if self.foto_ambiente and not self.foto_ambiente._committed:
            self.foto_ambiente_sha256 = calcular_sha256_arquivo(self.foto_ambiente.file)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.nome_cafeteria

    def detalhes(self):
        return {
            'responsavel': self.responsavel,
            'nome_cafeteria': self.nome_cafeteria,
            'endereco': self.endereco,
            'descricao': self.descricao,
            'email': self.email,
            'whatsapp': self.whatsapp,
            'horas_funcionamento': self.horas_funcionamento,
            'link_redesocial': self.link_redesocial,
            'foto_ambiente': self.foto_ambiente.url if self.foto_ambiente else None,
            'cnpj': self.cnpj,
        }
    def get_short_description(self):
        if len(self.descricao) > 70:
            return self.descricao[:70].__add__("...")
        else:
            return self.descricao
    
    def avaliacoes_publicadas(self):
        return self.avaliacao_set.filter(classificacao_ia='aprovado').order_by('-data_avaliacao')

    def media_avaliacoes(self):
        media = self.avaliacoes_publicadas().aggregate(Avg('avaliacao'))['avaliacao__avg']
        if media is not None:
            return round(media, 1)
        return None

    def media_valor_gasto(self):
        faixas = {
            '1-20': 10,
            '20-40': 30,
            '40-60': 50,
            '60-80': 70,
            '80-100': 90,
            '100-120': 110,
            '120-140': 130,
            '140-160': 150,
            '160-180': 170,
            '180-200': 190,
            '200+': 210
        }
        valores_gasto = self.avaliacoes_publicadas().values_list('valor_gasto', flat=True)
        valores_numericos = [faixas[v] for v in valores_gasto if v in faixas]
        if valores_numericos:
            media_numerica = sum(valores_numericos) / len(valores_numericos)
            for faixa, valor in faixas.items():
                if media_numerica <= valor:
                    return faixa
            return '200+'
        return None

class Favorito(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    cafe = models.ForeignKey(Cafe, on_delete=models.CASCADE)

    def detalhes(self):
        return {
            'nome': self.cafe.nome_cafeteria,
            'endereco': self.cafe.endereco,
            'descricao': self.cafe.descricao,
            'email': self.cafe.email,
            'whatsapp': self.cafe.whatsapp,
            'horas_funcionamento': self.cafe.horas_funcionamento,
            'link_redesocial': self.cafe.link_redesocial,
            'foto_ambiente': self.cafe.foto_ambiente.url if self.cafe.foto_ambiente else None,
        }

    def __str__(self):
        return f'{self.usuario.username} - {self.cafe.nome_cafeteria}'

class Historico(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    cafe = models.ForeignKey(Cafe, on_delete=models.CASCADE)
    visited_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('usuario', 'cafe', 'visited_at')  # Evita duplicatas exatas

    def detalhes(self):
        return {
            'nome': self.cafe.nome_cafeteria,
            'endereco': self.cafe.endereco,
            'descricao': self.cafe.descricao,
            'email': self.cafe.email,
            'whatsapp': self.cafe.whatsapp,
            'horas_funcionamento': self.cafe.horas_funcionamento,
            'link_redesocial': self.cafe.link_redesocial,
            'foto_ambiente': self.cafe.foto_ambiente.url if self.cafe.foto_ambiente else None,
        }

    def __str__(self):
        return f'{self.usuario.username} - {self.cafe.nome_cafeteria}'

class ReservaCafe(models.Model):
    cafe = models.ForeignKey(Cafe, on_delete=models.PROTECT)
    cliente = models.ForeignKey(UserCliente, on_delete=models.PROTECT)
    # Dados pessoais da reserva cifrados em repouso (criptografia simétrica
    # Fernet/AES). Ver apps/crypto_fields.py para a justificativa completa.
    nome_cliente = EncryptedCharField(blank=True, null=True)
    data_reserva = models.DateField()
    horario_reserva = models.TimeField()
    numero_de_pessoas = models.PositiveIntegerField(default=0)
    observacao = EncryptedTextField(blank=False, default='Descrição não informada')


    @property
    def status(self):
        hoje = datetime.now().date()
        hora = datetime.now().time()
        if self.data_reserva < hoje:
            return "Reserva terminada"
        elif self.data_reserva == hoje and self.horario_reserva < hora:
            return "Reserva terminada"
        elif self.data_reserva == hoje and self.horario_reserva > hora:
            return "Reserva para hoje"
        else:
            return "Reserva futura"

    @classmethod
    def minhas_reservas(cls, cliente_email):
        return cls.objects.filter(cliente__email_hash=calcular_hash_busca(cliente_email))

    def __str__(self):
        return f"Reserva no {self.cafe.nome_cafeteria} por {self.cliente.nome_completo}"
    
class Avaliacao(models.Model):
    STATUS_MODERACAO = [
        ('pendente', 'Pendente'),
        ('aprovado', 'Aprovado'),
        ('rejeitado', 'Rejeitado'),
    ]

    cafe = models.ForeignKey(Cafe, on_delete=models.CASCADE)
    cliente = models.ForeignKey(UserCliente, on_delete=models.CASCADE)
    avaliacao = models.IntegerField(choices=[(i, i) for i in range(1, 6)], default=1)
    # Cifrados em repouso: comentário livre pode conter dado pessoal, e
    # valor_gasto nunca é consultado por valor (só agregado em Python).
    comentario = EncryptedTextField(blank=True, null=True)
    valor_gasto = EncryptedCharField(blank=True, null=True)
    data_avaliacao = models.DateTimeField(auto_now_add=True)
    foto_avaliacao= models.ImageField(upload_to=upload_foto_avaliacao, blank=True, null=True, validators=[validar_conteudo_imagem])
    # SHA-256 do foto_avaliacao calculado no upload, para verificar depois se o arquivo em disco foi adulterado.
    foto_avaliacao_sha256 = models.CharField(max_length=64, blank=True, null=True)
    classificacao_ia = models.CharField(max_length=10, choices=STATUS_MODERACAO, default='pendente')
    justificativa_ia = models.TextField(blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.foto_avaliacao and not self.foto_avaliacao._committed:
            self.foto_avaliacao_sha256 = calcular_sha256_arquivo(self.foto_avaliacao.file)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Avaliação de {self.cliente.nome_completo} para {self.cafe.nome_cafeteria}"


class MensagemPrivada(models.Model):
    """Mensagem privada de um cliente para o dono de uma cafeteria.

    Cifrada com o algoritmo próprio do Projeto 2 (ver mensageria_cripto.py
    -- rede de substituição-permutação feita à mão, com chave dinâmica).
    Diferente da criptografia Fernet usada nos demais campos do app: esta
    existe especificamente para o exercício de cripto/ataques do Projeto 2.
    """
    remetente = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mensagens_enviadas')
    cafe = models.ForeignKey(Cafe, on_delete=models.CASCADE, related_name='mensagens_recebidas')
    texto_cifrado = models.TextField()
    chave = models.CharField(max_length=255)
    enviada_em = models.DateTimeField(auto_now_add=True)
    lida = models.BooleanField(default=False)

    def texto_decifrado(self, usuario='', ip=None):
        return decifrar(self.texto_cifrado, self.chave, usuario=usuario, ip=ip)

    def __str__(self):
        return f"Mensagem de {self.remetente.username} para {self.cafe.nome_cafeteria}"


class EventoSeguranca(models.Model):
    """Tabela central de eventos do SecureAI Lab (camada "Big Data").

    Uma linha por evento relevante para segurança: operações criptográficas,
    autenticação, controle de acesso, integridade de arquivos, moderação por
    IA, ataques simulados e anomalias detectadas. É a fonte de dados da IA de
    anomalias e do dashboard.

    PRIVACIDADE: não grava texto em claro de mensagens, chaves
    criptográficas ou senhas. `detalhes` guarda só metadados (tamanhos,
    tempos, contagens, nomes de objetos).
    """
    CIFRAGEM = 'cifragem'
    DECIFRAGEM = 'decifragem'
    FALHA_DECIFRAGEM = 'falha_decifragem'
    LOGIN_SUCESSO = 'login_sucesso'
    LOGIN_FALHA = 'login_falha'
    LOGIN_BLOQUEADO = 'login_bloqueado'
    ACESSO_NEGADO = 'acesso_negado'
    INTEGRIDADE_VIOLADA = 'integridade_violada'
    MODERACAO_IA = 'moderacao_ia'
    ESTEGANOGRAFIA = 'esteganografia'
    ATAQUE_FORCA_BRUTA = 'ataque_forca_bruta'
    ATAQUE_DIFERENCIAL = 'ataque_diferencial'
    ATAQUE_ESTATISTICO = 'ataque_estatistico'
    ANOMALIA = 'anomalia'

    TIPOS = [
        (CIFRAGEM, 'Cifragem'),
        (DECIFRAGEM, 'Decifragem'),
        (FALHA_DECIFRAGEM, 'Falha de decifragem'),
        (LOGIN_SUCESSO, 'Login bem-sucedido'),
        (LOGIN_FALHA, 'Falha de login'),
        (LOGIN_BLOQUEADO, 'Login bloqueado (CAPTCHA)'),
        (ACESSO_NEGADO, 'Acesso negado'),
        (INTEGRIDADE_VIOLADA, 'Integridade violada'),
        (MODERACAO_IA, 'Moderação por IA'),
        (ESTEGANOGRAFIA, 'Esteganografia'),
        (ATAQUE_FORCA_BRUTA, 'Ataque: força bruta'),
        (ATAQUE_DIFERENCIAL, 'Ataque: diferencial'),
        (ATAQUE_ESTATISTICO, 'Ataque: estatístico'),
        (ANOMALIA, 'Anomalia detectada'),
    ]

    INFO, ALERTA, CRITICO = 'info', 'alerta', 'critico'
    SEVERIDADES = [(INFO, 'Info'), (ALERTA, 'Alerta'), (CRITICO, 'Crítico')]

    # Categoria = camada do sistema que gerou o evento (facilita agrupar).
    CATEGORIAS = [
        ('criptografia', 'Criptografia'),
        ('autenticacao', 'Autenticação'),
        ('autorizacao', 'Autorização'),
        ('integridade', 'Integridade'),
        ('ia', 'Inteligência Artificial'),
        ('esteganografia', 'Esteganografia'),
        ('ataque', 'Ataques simulados'),
        ('anomalia', 'Anomalias'),
    ]

    criado_em = models.DateTimeField(default=timezone.now, db_index=True)
    tipo = models.CharField(max_length=30, choices=TIPOS, db_index=True)
    categoria = models.CharField(max_length=20, choices=CATEGORIAS, db_index=True)
    severidade = models.CharField(max_length=10, choices=SEVERIDADES, default=INFO)
    sucesso = models.BooleanField(default=True)
    # Texto (não FK): sobrevive à exclusão do usuário e permite registrar
    # tentativas com usuário inexistente (e-mails digitados ficam pseudonimizados).
    usuario = models.CharField(max_length=150, blank=True, default='', db_index=True)
    ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    # Módulo/fluxo de origem (ex.: "mensageria_cripto", "login_view").
    origem = models.CharField(max_length=60, blank=True, default='')
    duracao_ms = models.FloatField(null=True, blank=True)
    # Metadados livres (JSON). Ver aviso de privacidade acima.
    detalhes = models.JSONField(default=dict, blank=True)
    # True = evento sintético (gerar_eventos_simulados); False = real.
    simulado = models.BooleanField(default=False, db_index=True)

    class Meta:
        ordering = ['-criado_em']
        verbose_name = 'Evento de segurança'
        verbose_name_plural = 'Eventos de segurança'
        indexes = [
            models.Index(fields=['tipo', 'criado_em']),
            models.Index(fields=['ip', 'criado_em']),
            models.Index(fields=['usuario', 'criado_em']),
        ]

    def __str__(self):
        return f'[{self.criado_em:%Y-%m-%d %H:%M:%S}] {self.tipo} usuario={self.usuario or "-"} ip={self.ip or "-"}'
