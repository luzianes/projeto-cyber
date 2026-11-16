from django.contrib import admin
from .models import UserCliente, Cafe, Favorito, Historico, ReservaCafe, Avaliacao, MensagemPrivada, EventoSeguranca

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


class EventoSegurancaAdmin(admin.ModelAdmin):
    """Somente leitura: eventos são trilha de auditoria, não devem ser editados."""
    list_display = ('criado_em', 'tipo', 'severidade', 'sucesso', 'usuario', 'ip', 'origem', 'simulado')
    list_filter = ('tipo', 'severidade', 'categoria', 'sucesso', 'simulado')
    search_fields = ('usuario', 'ip', 'origem')
    date_hierarchy = 'criado_em'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


if EventoSeguranca not in admin.site._registry:
    admin.site.register(EventoSeguranca, EventoSegurancaAdmin)