"""
Corrige a mensageria a partir dos ataques (docs/ATAQUES_CIFRA.md):

1. `chave` passa a ser EncryptedCharField (Fernet + FIELD_ENCRYPTION_KEY): a
   chave de cada mensagem deixa de ficar em claro ao lado do texto cifrado.
2. Toda mensagem existente, cifrada com a v1, é decifrada e recifrada com a
   v2 (128 bits, avalanche, autenticada) usando uma chave nova.

Reversível: o caminho de volta recifra com a v1 e grava a chave em claro,
como o código antigo espera. Precisa da FIELD_ENCRYPTION_KEY quando há
mensagens no banco. Usa apps.cifra_v1_legada: não remover aquele módulo
enquanto esta migration existir.
"""
from django.db import migrations
from django.db.models import Value

import apps.crypto_fields


def recifrar_para_v2(apps, schema_editor):
    from apps.eventos import silenciar_eventos
    from apps.mensageria_cripto import migrar_da_v1

    MensagemPrivada = apps.get_model('apps', 'MensagemPrivada')
    convertidas, falhas = 0, 0
    with silenciar_eventos():
        for mensagem in MensagemPrivada.objects.all().iterator():
            # `chave` legada está em claro; o campo cifrado a devolve como está.
            try:
                mensagem.texto_cifrado, mensagem.chave = migrar_da_v1(mensagem.texto_cifrado, mensagem.chave)
            except ValueError:
                falhas += 1  # já ilegível antes (dado corrompido): fica como está
                continue
            mensagem.save(update_fields=['texto_cifrado', 'chave'])
            convertidas += 1
    if convertidas or falhas:
        print(f'\n  mensagens recifradas com a v2: {convertidas}; ilegíveis mantidas: {falhas}')


def recifrar_para_v1(apps, schema_editor):
    from apps.eventos import silenciar_eventos
    from apps.mensageria_cripto import migrar_para_v1

    MensagemPrivada = apps.get_model('apps', 'MensagemPrivada')
    with silenciar_eventos():
        for mensagem in MensagemPrivada.objects.all().iterator():
            try:
                cifrado, chave = migrar_para_v1(mensagem.texto_cifrado, mensagem.chave)
            except ValueError:
                continue
            # Value() grava a chave crua, sem passar pela cifragem do campo:
            # depois desta etapa a coluna volta a ser CharField em claro.
            MensagemPrivada.objects.filter(pk=mensagem.pk).update(
                texto_cifrado=cifrado, chave=Value(chave))


class Migration(migrations.Migration):

    dependencies = [
        ('apps', '0055_eventoseguranca'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mensagemprivada',
            name='chave',
            field=apps.crypto_fields.EncryptedCharField(),
        ),
        migrations.RunPython(recifrar_para_v2, recifrar_para_v1),
    ]
