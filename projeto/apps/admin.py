from django.contrib import admin
from .models import UserCliente, Cafe, Favorito, Historico, ReservaCafe, Avaliacao, MensagemPrivada

# Função para registrar um modelo se não estiver registrado
def register_model(admin_site, model):
    if model not in admin_site._registry:
        admin_site.register(model)
    else:
        print(f"O modelo {model.__name__} já está registrado.")

# Registrando os modelos
register_model(admin.site, UserCliente)
register_model(admin.site, Cafe)
register_model(admin.site, Favorito)
register_model(admin.site, Historico)
register_model(admin.site, ReservaCafe)
register_model(admin.site, Avaliacao)

class MensagemPrivadaAdmin(admin.ModelAdmin):
    
    list_display = ('remetente', 'cafe', 'enviada_em', 'lida', 'texto_cifrado')
    readonly_fields = ('texto_cifrado', 'chave', 'remetente', 'cafe', 'enviada_em')

if MensagemPrivada not in admin.site._registry:
    admin.site.register(MensagemPrivada, MensagemPrivadaAdmin)