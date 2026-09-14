from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.db.models import Avg
from datetime import datetime

from .crypto_fields import EncryptedCharField, EncryptedTextField
from .integrity import calcular_sha256_arquivo

class UserCliente(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    nome_completo = models.CharField(max_length=150, default="Desconhecido")
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255, null=True)
    confirm_password = models.CharField(max_length=255, null=True)
    is_business = models.BooleanField(default=False)
    profile_image = models.ImageField(upload_to='profile_image/', blank=True, null=True)
    # SHA-256 do profile_image calculado no upload, para verificar depois se o arquivo em disco foi adulterado.
    profile_image_sha256 = models.CharField(max_length=64, blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.profile_image and not self.profile_image._committed:
            self.profile_image_sha256 = calcular_sha256_arquivo(self.profile_image.file)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email

class Cafe(models.Model):
    responsavel = models.CharField(max_length=100, blank=False, default='Nome do responsável não informado')
    nome_cafeteria = models.CharField(max_length=100, blank=False, default='Nome não informado')
    endereco = models.CharField(max_length=100, blank=False, default='Endereço não informado')
    descricao = models.TextField(blank=False, default='Descrição não informada')
    email = models.EmailField()
    whatsapp = models.CharField(max_length=13, default='5500000000000')
    horas_funcionamento = models.CharField(max_length=100, blank=False, default='Horário não informado')
    link_redesocial = models.URLField(max_length=200, blank=True)
    foto_ambiente = models.ImageField(upload_to='fotos_cafeterias/', blank=True, null=True)
    # SHA-256 do foto_ambiente calculado no upload, para verificar depois se o arquivo em disco foi adulterado.
    foto_ambiente_sha256 = models.CharField(max_length=64, blank=True, null=True)
    cnpj = models.CharField(max_length=14, unique=True, default='00000000000000')
    site_cafeteria = models.URLField(max_length=200, blank=True)
    empresario = models.ForeignKey(UserCliente, on_delete=models.CASCADE, related_name='cafeterias', null=True, blank=True)

    def save(self, *args, **kwargs):
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
        return cls.objects.filter(cliente__email=cliente_email)

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
    comentario = models.TextField(blank=True, null=True)
    valor_gasto = models.CharField(max_length=50, blank=True, null=True)
    data_avaliacao = models.DateTimeField(auto_now_add=True)
    foto_avaliacao= models.ImageField(upload_to='fotos_experiencias/', blank=True, null=True)
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


