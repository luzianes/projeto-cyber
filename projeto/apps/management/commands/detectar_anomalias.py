"""
Roda a IA de anomalias sobre a tabela de eventos e grava os alertas.

    python manage.py detectar_anomalias                      # detecta e grava eventos `anomalia`
    python manage.py detectar_anomalias --avaliar            # + mede acerto contra o gabarito simulado
    python manage.py detectar_anomalias --avaliar --nao-gravar --json resultado.json
    python manage.py detectar_anomalias --sem-simulados      # só eventos reais do sistema
    python manage.py detectar_anomalias --limpar             # apaga os alertas gerados pela IA

Precisa de scikit-learn: pip install -r requirements-ia.txt
"""
import json

from django.core.management.base import BaseCommand

from apps import deteccao_anomalias as da
from apps.models import EventoSeguranca


class Command(BaseCommand):
    help = 'Detecta comportamento anômalo nos eventos de segurança (regras + Isolation Forest).'

    def add_arguments(self, parser):
        parser.add_argument('--janela', type=int, default=da.JANELA_MINUTOS, help='minutos por janela')
        parser.add_argument('--contaminacao', type=float, default=da.CONTAMINACAO,
                            help='fração esperada de janelas suspeitas (hiperparâmetro do modelo)')
        parser.add_argument('--sem-simulados', action='store_true', help='ignora eventos sintéticos')
        parser.add_argument('--nao-gravar', action='store_true', help='não grava eventos `anomalia`')
        parser.add_argument('--avaliar', action='store_true', help='mede acerto contra o gabarito simulado')
        parser.add_argument('--json', help='salva o resultado completo neste arquivo')
        parser.add_argument('--limpar', action='store_true', help='apaga os alertas gerados pela IA e sai')
        parser.add_argument('--mostrar', type=int, default=10, help='quantos alertas listar')

    def handle(self, *args, **o):
        w = self.stdout.write
        if o['limpar']:
            n, _ = EventoSeguranca.objects.filter(tipo=EventoSeguranca.ANOMALIA, origem=da.ORIGEM).delete()
            w(self.style.SUCCESS(f'{n} alertas da IA apagados.'))
            return

        info = da.executar(minutos=o['janela'], incluir_simulados=not o['sem_simulados'],
                           gravar=not o['nao_gravar'], com_avaliacao=o['avaliar'],
                           contaminacao=o['contaminacao'])

        w(self.style.MIGRATE_HEADING('== IA de anomalias =='))
        w(f"Janelas de {o['janela']} min: {info['janelas']} | enviadas ao modelo "
          f"(>= {da.MIN_EVENTOS} eventos): {info['janelas_ativas']}")
        if not info['modelo_usado']:
            w(self.style.WARNING(
                f"Menos de {da.MIN_JANELAS_MODELO} janelas ativas: Isolation Forest não foi treinado, "
                'só as regras de assinatura foram aplicadas.'))
        w(f"Anomalias: {info['anomalias']}")
        if o['nao_gravar']:
            w('Nada gravado (--nao-gravar).')
        else:
            w(f"Gravadas: {info['novas']} novas | {info['repetidas']} já registradas antes")

        alertas = sorted(info['alertas'], key=lambda a: -(a['score'] or 1))
        if alertas and o['mostrar']:
            w(f"\nPrincipais alertas (de {len(alertas)}):")
            for a in alertas[:o['mostrar']]:
                score = f"{a['score']:.3f}" if a['score'] is not None else '  -  '
                w(f"  {a['janela_inicio'][:16]}  {a['entidade']:<16} score={score} "
                  f"{a['metodo']:<22} {a['descricao']}")

        av = info['avaliacao']
        if o['avaliar']:
            if not av:
                w(self.style.WARNING('\nSem dados simulados com gabarito para avaliar.'))
            else:
                w(self.style.MIGRATE_HEADING('\n== Avaliação contra o gabarito =='))
                w(f"Janelas avaliadas: {av['janelas_avaliadas']} | anômalas no gabarito: {av['janelas_anomalas']}")
                w(f"{'abordagem':<18} {'precisão':>9} {'recall':>8} {'F1':>7} {'alertas':>8} {'falsos+':>8}")
                for nome in ('regras', 'isolation_forest', 'hibrido'):
                    m = av[nome]
                    w(f"{nome:<18} {m['precisao']:>9.3f} {m['recall']:>8.3f} {m['f1']:>7.3f} "
                      f"{m['alertas']:>8} {m['fp']:>8}")
                w(f"Janelas anômalas que só o Isolation Forest pegou (nenhuma regra disparou): "
                  f"{av['so_o_modelo_detectou']}")
                w('\nDetectado por cenário (janelas detectadas / total):')
                for cenario, c in av['por_cenario'].items():
                    w(f"  {cenario:<28} híbrido {c['hibrido']:>3}/{c['janelas']:<5} "
                      f"IF {c['isolation_forest']:>3}  regras {c['regras']:>3}")

        if o['json']:
            with open(o['json'], 'w', encoding='utf-8') as f:
                json.dump(info, f, ensure_ascii=False, indent=2, default=str)
            w(self.style.SUCCESS(f"\nResultado salvo em {o['json']}"))
