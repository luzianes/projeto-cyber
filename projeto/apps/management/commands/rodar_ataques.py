"""
Roda os ataques à cifra própria da mensageria (Pessoa 2) e responde: a cifra
tem efeito avalanche? É segura? Detalhes em docs/ATAQUES_CIFRA.md.

    python manage.py rodar_ataques                               # os três ataques + veredito
    python manage.py rodar_ataques --ataque diferencial          # só um (pode repetir a opção)
    python manage.py rodar_ataques --bytes-desconhecidos 3       # força bruta maior (~25 min)
    python manage.py rodar_ataques --json resultados_ataques.json   # para o dashboard
    python manage.py rodar_ataques --nao-registrar               # não grava eventos

Cada ataque grava UM evento-resumo (ataque_diferencial, ataque_forca_bruta,
ataque_estatistico) na tabela EventoSeguranca.
"""
import json

from django.core.management.base import BaseCommand, CommandError

from apps import ataques_cripto as ac
from apps.ataques_cripto import num


class Command(BaseCommand):
    help = 'Ataques força bruta, diferencial e estatístico contra a cifra da mensageria.'

    def add_arguments(self, parser):
        parser.add_argument('--ataque', action='append', choices=list(ac.ATAQUES),
                            help='ataque a rodar (padrão: todos)')
        parser.add_argument('--seed', type=int, default=42, help='semente (amostras reproduzíveis)')
        parser.add_argument('--amostras', type=int, default=200, help='diferencial: blocos sorteados')
        parser.add_argument('--bytes-desconhecidos', type=int, default=2,
                            help='força bruta real: bytes secretos da chave reduzida (2 = 65.536 chaves)')
        parser.add_argument('--blocos-conhecidos', type=int, default=3,
                            help='dividir para conquistar: blocos de 8 bytes de texto conhecido (2 a 4)')
        parser.add_argument('--mensagens', type=int, default=2000, help='estatístico: tamanho do corpus')
        parser.add_argument('--json', help='salva os resultados completos neste arquivo')
        parser.add_argument('--nao-registrar', action='store_true', help='não grava eventos na tabela')

    def handle(self, *args, **o):
        if not 1 <= o['bytes_desconhecidos'] <= ac.CHAVE:
            raise CommandError(f'--bytes-desconhecidos deve estar entre 1 e {ac.CHAVE}')
        if not 2 <= o['blocos_conhecidos'] <= 4:
            raise CommandError('--blocos-conhecidos deve estar entre 2 e 4')
        if o['amostras'] < 1 or o['mensagens'] < 3:
            raise CommandError('--amostras deve ser >= 1 e --mensagens >= 3')

        nomes = o['ataque'] or list(ac.ATAQUES)
        parametros = {
            'diferencial': {'amostras': o['amostras'], 'seed': o['seed']},
            'forca_bruta': {'bytes_desconhecidos': o['bytes_desconhecidos'],
                            'blocos_conhecidos': o['blocos_conhecidos'], 'seed': o['seed']},
            'estatistico': {'qtd_mensagens': o['mensagens'], 'seed': o['seed']},
        }
        resultados = {}
        for nome in dict.fromkeys(nomes):
            r = ac.executar(nome, registrar=not o['nao_registrar'], **parametros[nome])
            resultados[nome] = r
            getattr(self, f'_imprimir_{nome}')(r)
            self._imprimir_evento(r, o['nao_registrar'])

        if all(n in resultados for n in ac.ATAQUES):
            resultados['veredito'] = ac.veredito(
                resultados['diferencial'], resultados['forca_bruta'], resultados['estatistico'])
            self._imprimir_veredito(resultados['veredito'])

        if o['json']:
            with open(o['json'], 'w', encoding='utf-8') as f:
                json.dump(resultados, f, ensure_ascii=False, indent=2, default=str)
            self.stdout.write(self.style.SUCCESS(f"\nResultados salvos em {o['json']}"))

    # --- impressão ----------------------------------------------------------

    def _titulo(self, texto):
        self.stdout.write(self.style.MIGRATE_HEADING(f'\n== {texto} =='))

    def _resultado(self, vulneravel, texto):
        self.stdout.write(self.style.ERROR(texto) if vulneravel else self.style.SUCCESS(texto))

    def _imprimir_evento(self, r, nao_registrar):
        if nao_registrar:
            return
        if r['evento_id']:
            self.stdout.write(f"  -> evento registrado na tabela EventoSeguranca (id={r['evento_id']})")
        else:
            self.stdout.write(self.style.WARNING(
                '  -> evento NÃO registrado (tabela ausente? rode `manage.py migrate`; '
                'detalhe em logs/security.log)'))

    def _imprimir_diferencial(self, r):
        w = self.stdout.write
        t, c, m = r['texto'], r['chave'], r['mensagem_cbc']
        self._titulo('1. Ataque diferencial (efeito avalanche)')
        w(f"Inverter 1 bit do TEXTO (mesma chave, mesmo IV): {num(t['bits_alterados_media'], 2)} de 64 bits "
          f"mudam ({num(t['percentual_bits'], 1)}%; ideal ~50%). Máx. de bytes alterados no bloco: "
          f"{t['bytes_alterados_max']} de 8.")
        w(f"Inverter 1 bit da CHAVE (mesmo texto): {num(c['bits_alterados_media'], 2)} de 64 bits mudam "
          f"({num(c['percentual_bits'], 1)}%). Máx. de bytes alterados: {c['bytes_alterados_max']} de 8.")
        w('Byte de entrada -> bytes de saída afetados: ' + ', '.join(
            f'{j}->{s}' for j, s in enumerate(t['mapa_entrada_saida'])))
        w(f"  bytes que saem na mesma posição em que entraram: {t['bytes_que_nao_mudam_de_posicao']}")
        w(f"Mensagem de 5 blocos (CBC), 1 bit alterado no 1º bloco: {num(m['percentual_bits'], 1)}% dos "
          f"bits mudam, no máx. {m['bytes_alterados_max_por_bloco']} byte por bloco. Alterar o último "
          f"bloco deixa os anteriores intactos: {'sim' if m['blocos_anteriores_intactos'] else 'não'}.")
        w(f"Comparação ingênua (cifrar() 2x, IV sorteado a cada vez): "
          f"{num(r['ingenuo_iv_aleatorio']['percentual_bits'], 1)}% -> parece avalanche, mas é só o IV "
          f"aleatório.")
        s = r['sbox']
        w(f"S-box: uniformidade diferencial {s['uniformidade_diferencial']} (o melhor diferencial passa "
          f"com probabilidade {num(100 * s['probabilidade'], 1)}%; no AES: {s['referencia_aes']}).")
        mal = r['maleabilidade']
        w(f"Maleabilidade (sem a chave, alterando 1 byte do IV): "
          f"'{mal['original']}' -> '{mal['adulterado']}'")
        self._resultado(not r['tem_avalanche'],
                        f"Efeito avalanche: {'SIM' if r['tem_avalanche'] else 'NÃO'}")

    def _imprimir_forca_bruta(self, r):
        w = self.stdout.write
        e, red, dc = r['estimativa'], r['reduzida'], r['dividir_conquistar']
        self._titulo('2. Ataque de força bruta')
        w(f"(a) Chave reduzida a {red['bits_desconhecidos']} bits ({num(red['espaco'])} chaves), só com o "
          f"texto cifrado: achada em {num(red['tentativas'])} tentativas, {num(red['tempo_s'], 2)} s "
          f"-> {'QUEBROU' if red['quebrou'] else 'não quebrou'}")
        w(f"    texto recuperado: {red['texto_recuperado']!r}")
        w(f"(b) Chave real de {e['espaco_chaves_bits']} bits = {num(e['espaco_chaves'])} chaves. "
          f"Taxa medida: {num(e['taxa_chaves_por_s'])} chaves/s (decifrar() em Python, 1 núcleo).")
        w(f"    Tempo estimado: {num(e['anos_caso_medio'])} anos em média "
          f"({num(e['anos_pior_caso'])} no pior caso). Mínimo recomendado hoje: "
          f"{e['minimo_recomendado_bits']} bits.")
        w(f"(c) Dividir para conquistar, chave completa de {e['espaco_chaves_bits']} bits, com "
          f"{dc['bytes_texto_conhecido']} bytes de texto conhecido (início da mensagem):")
        w(f"    candidatos por byte do bloco: {dc['candidatos_por_posicao']} -> "
          f"{dc['chaves_coerentes']} chave(s) coerente(s), {num(dc['tempo_s'], 2)} s "
          f"-> {'QUEBROU' if dc['quebrou'] else 'não quebrou'}")
        w(f"    mensagem inteira recuperada: {dc['texto_recuperado']!r}")
        self._resultado(r['vulnerabilidade_encontrada'],
                        f"Força bruta: {'QUEBROU a chave' if dc['quebrou'] else 'chave não recuperada'}")

    def _imprimir_estatistico(self, r):
        w = self.stdout.write
        self._titulo('3. Ataque estatístico (análise de frequência)')
        w(f"Corpus: {num(r['resumo']['mensagens'])} mensagens, cada uma com chave nova.")
        for nome, p in (('Texto claro  ', r['texto_claro']), ('Texto cifrado', r['texto_cifrado'])):
            w(f"{nome}: {num(p['bytes'])} bytes, {p['valores_distintos']} valores distintos, entropia "
              f"{num(p['entropia_bits_por_byte'], 3)} bits/byte, qui² = {num(p['qui_quadrado'], 1)} "
              f"(p = {num(p['p_valor'], 4)})")
            w('               mais frequentes: ' + ', '.join(
                f"{b!r} {num(pct, 2)}%" for b, pct in p['mais_comuns_pct']))
        w(f"Distribuição do cifrado é uniforme (p > 0,01)? {'SIM' if r['uniforme'] else 'NÃO'} "
          f"(máximo teórico de entropia: 8 bits/byte)")
        b = r['blocos_repetidos']
        w(f"8 blocos de texto idênticos -> blocos cifrados distintos: {b['distintos_com_cbc']} com CBC, "
          f"{b['distintos_sem_cbc']} sem o encadeamento (o padrão ficaria visível).")
        w(f"Mesma mensagem e mesma chave cifradas 2x: "
          f"{num(r['mesma_mensagem_duas_vezes_pct_bytes_iguais'], 1)}% de bytes iguais.")
        tam = r['tamanho']
        w(f"Vazamento de tamanho: em {num(tam['mensagens_com_tamanho_deduzido'])} de "
          f"{num(r['resumo']['mensagens'])} mensagens o tamanho do texto foi deduzido só do cifrado, "
          f"com margem de {tam['incerteza_bytes']} bytes.")
        self._resultado(r['vulnerabilidade_encontrada'],
                        'Análise de frequência: ' + ('encontrou padrão' if r['vulnerabilidade_encontrada']
                                                     else 'NÃO quebrou'))

    def _imprimir_veredito(self, v):
        w = self.stdout.write
        self._titulo('Veredito')
        w(f"Tem efeito avalanche? {'SIM' if v['tem_avalanche'] else 'NÃO'}")
        w(f"É segura?             {'SIM' if v['seguro'] else 'NÃO'}")
        for motivo in v['motivos']:
            w(f'  - {motivo}')
