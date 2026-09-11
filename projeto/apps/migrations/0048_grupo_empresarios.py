from django.db import migrations


def criar_grupo_empresarios(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.get_or_create(name='Empresários')


def remover_grupo_empresarios(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(name='Empresários').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('apps', '0047_avaliacao_classificacao_ia_and_more'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.RunPython(criar_grupo_empresarios, remover_grupo_empresarios),
    ]
