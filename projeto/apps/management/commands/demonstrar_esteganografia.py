"""
Demonstra e mede a esteganografia LSB (Pessoa 3) junto com a cifra da
mensageria: esconde uma mensagem cifrada numa imagem, mede capacidade, MSE e
PSNR e confere a extração com chave, sem chave, com chave errada e depois de
alterações na imagem (1 bit, recompressão JPEG, redimensionamento).

    python manage.py demonstrar_esteganografia
    python manage.py demonstrar_esteganografia --imagem foto.png --saida ../evidencias/09-esteganografia/

Usa o serviço real (esteganografia_servico), com o registro de eventos
suspenso: é uma medição, não uso do sistema.
"""
import random
import time
from io import BytesIO
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from PIL import Image, ImageChops

from apps import esteganografia_servico as servico
from apps import mensageria_cripto as cripto
from apps.ataques_cripto import gerar_mensagens, num
from apps.esteganografia import (
    TAMANHO_CABECALHO, ErroEsteganografia, calcular_metricas, capacidade_imagem,
    carregar_imagem, ocultar_texto,
)
from apps.eventos import silenciar_eventos

IMAGEM_PADRAO = Path(settings.BASE_DIR) / 'apps' / 'static' / 'images' / 'img-home-cliente.png'
MENSAGEM_CURTA = 'Olá! Quero reservar uma mesa para 4 pessoas no sábado às 20h. Meu telefone é (81) 90000-0000.'


def _png(imagem):
    saida = BytesIO()
    imagem.save(saida, format='PNG')
    return saida.getvalue()


def _bits_alterados(original, modificada):
    """Quantas amostras RGB mudaram (cada uma muda no máximo 1 unidade)."""
    diferenca = ImageChops.difference(original.convert('RGB'), modificada.convert('RGB'))
    histograma = diferenca.histogram()
    maior = max((i % 256 for i, n in enumerate(histograma) if n and i % 256), default=0)
    return sum(n for i, n in enumerate(histograma) if i % 256), maior, diferenca


class Command(BaseCommand):
    help = 'Mede a esteganografia LSB (capacidade, PSNR) e testa a extração.'

    def add_arguments(self, parser):
        parser.add_argument('--imagem', default=str(IMAGEM_PADRAO), help='imagem de capa (PNG, JPEG, BMP, WebP)')
        parser.add_argument('--saida', help='pasta para salvar a comparação visual (original, com mensagem, diferença)')
        parser.add_argument('--seed', type=int, default=42)

    def handle(self, *args, **o):
        try:
            with silenciar_eventos():
                self._executar(o)
        except (ErroEsteganografia, OSError) as exc:
            raise CommandError(str(exc)) from None

    def _executar(self, o):
        w = self.stdout.write
        dados = Path(o['imagem']).read_bytes()
        original = carregar_imagem(dados)
        capacidade = capacidade_imagem(original)
        w(self.style.MIGRATE_HEADING('== Imagem de capa =='))
        w(f"{Path(o['imagem']).name}: {original.width} x {original.height} px, {original.mode}, "
          f"{num(len(dados) / 1024)} KiB")
        w(f"Capacidade: {num(original.width * original.height * 3)} bits menos significativos (3 por pixel) "
          f"= {num(capacidade)} bytes úteis, descontado o cabeçalho de {TAMANHO_CABECALHO} bytes")

        rng = random.Random(o['seed'])
        # Mensagem longa: perto do limite do serviço (64 KiB), sem passar da
        # capacidade (o envelope em base64 ocupa ~1,34x o texto).
        alvo = min(servico.MAX_MENSAGEM_BYTES - 2000, int(capacidade * 0.7))
        longa = ''
        while len((longa + ' ').encode('utf-8')) < alvo:
            longa += gerar_mensagens(1, rng)[0] + ' '
        casos = [('curta', MENSAGEM_CURTA), ('longa', longa.strip())]

        w(self.style.MIGRATE_HEADING('\n== Ocultação (cifra v2 + envelope autenticado + LSB) =='))
        w(f"{'mensagem':<10}{'texto':>10}{'oculto':>10}{'uso':>9}{'amostras alteradas':>20}{'MSE':>11}"
          f"{'PSNR':>10}{'tempo':>9}")
        ocultos = {}
        for nome, mensagem in casos:
            inicio = time.perf_counter()
            r = servico.ocultar_mensagem(BytesIO(dados), mensagem)
            tempo = time.perf_counter() - inicio
            modificada = carregar_imagem(r['imagem_png'])
            alteradas, maior, diferenca = _bits_alterados(original, modificada)
            m = r['metricas']
            ocultos[nome] = (r, mensagem, modificada, diferenca)
            w(f"{nome:<10}{num(len(mensagem.encode('utf-8'))):>10}{num(m['payload_bytes']):>10}"
              f"{num(m['capacidade_utilizada_percentual'], 3) + '%':>9}"
              f"{num(alteradas) + f' (±{maior})':>20}{num(m['mse'], 6):>11}{num(m['psnr'], 1) + ' dB':>10}"
              f"{num(1000 * tempo) + ' ms':>9}")

        # Pior caso da camada LSB: capacidade inteira ocupada (sem cifrar; o
        # serviço limita a mensagem a 64 KiB, bem abaixo da capacidade desta imagem).
        cheio = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(capacidade))
        r_cheio = ocultar_texto(original, cheio)
        alteradas, maior, _ = _bits_alterados(original, carregar_imagem(r_cheio.png))
        w(f"{'cheia*':<10}{num(capacidade):>10}{num(r_cheio.payload_bytes):>10}{'100%':>9}"
          f"{num(alteradas) + f' (±{maior})':>20}{num(r_cheio.mse, 6):>11}{num(r_cheio.psnr, 1) + ' dB':>10}")
        w('* capacidade inteira preenchida direto na camada LSB, para medir o pior caso de qualidade.')
        w('PSNR acima de ~40 dB é considerado imperceptível; cada amostra RGB muda no máximo 1 unidade (de 0 a 255).')

        w(self.style.MIGRATE_HEADING('\n== Extração (mensagem curta) =='))
        r, mensagem, modificada, _ = ocultos['curta']
        png = r['imagem_png']

        def tentar(descricao, imagem_png, chave, esperado):
            try:
                extraido = servico.extrair_mensagem(BytesIO(imagem_png), chave)
                if extraido['mensagem'] is not None:
                    resultado = 'mensagem recuperada' + (' (idêntica)' if extraido['mensagem'] == mensagem else ' (DIFERENTE)')
                else:
                    resultado = 'texto cifrado recuperado, sem decifrar' + (
                        ' (idêntico ao oculto)' if extraido['texto_cifrado'] == r['texto_cifrado'] else '')
                ok = esperado == 'sucesso'
            except ErroEsteganografia as exc:
                resultado, ok = f'recusada: {exc.codigo}', esperado == exc.codigo or esperado == 'erro'
            marca = self.style.SUCCESS('OK  ') if ok else self.style.ERROR('FALHOU')
            w(f'{marca} {descricao:<46} -> {resultado}')

        tentar('com a chave certa', png, r['chave'], 'sucesso')
        tentar('sem chave', png, '', 'sucesso')
        tentar('com outra chave', png, cripto.gerar_chave(), 'autenticacao_invalida')
        um_bit = bytearray(modificada.tobytes())
        um_bit[TAMANHO_CABECALHO * 8 + 100] ^= 1  # 1 bit dentro dos dados ocultos
        tentar('1 bit alterado na imagem', _png(Image.frombytes(modificada.mode, modificada.size, bytes(um_bit))),
               r['chave'], 'integridade_invalida')
        jpeg = BytesIO()
        modificada.save(jpeg, format='JPEG', quality=95)
        tentar('recomprimida em JPEG (qualidade 95)', jpeg.getvalue(), r['chave'], 'erro')
        menor = modificada.resize((modificada.width - 1, modificada.height - 1))
        tentar('redimensionada em 1 pixel', _png(menor), r['chave'], 'erro')

        if o['saida']:
            pasta = Path(o['saida'])
            pasta.mkdir(parents=True, exist_ok=True)
            _, _, modificada, diferenca = ocultos['longa']
            # diferença ampliada: amostra alterada (±1) vira 255 para ficar visível
            ampliada = diferenca.point(lambda v: 255 if v else 0)
            largura = 900
            altura = round(original.height * largura / original.width)
            quadros = [im.convert('RGB').resize((largura, altura)) for im in (original, modificada, ampliada)]
            comparacao = Image.new('RGB', (largura, 3 * altura + 20), 'white')
            for i, quadro in enumerate(quadros):
                comparacao.paste(quadro, (0, i * (altura + 10)))
            comparacao.save(pasta / 'comparacao.jpg', quality=85, optimize=True)
            w(self.style.SUCCESS(f'\nComparação salva em {pasta / "comparacao.jpg"} '
                                 '(de cima para baixo: original, com a mensagem longa, diferença ampliada)'))
            mse, psnr = calcular_metricas(original, modificada)
            w(f'(conferência das métricas da mensagem longa: MSE {num(mse, 6)}, PSNR {num(psnr, 1)} dB)')
