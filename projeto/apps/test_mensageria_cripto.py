"""Cifra v2 da mensageria e migração das mensagens da v1."""
import base64
import importlib
import io
import os
from contextlib import redirect_stdout

from django.apps import apps as registro
from django.contrib.auth.models import User
from django.db import connection
from django.db.models import Value
from django.test import TestCase

from . import cifra_v1_legada as v1
from . import mensageria_cripto as mc
from .models import Cafe, EventoSeguranca, MensagemPrivada

migracao = importlib.import_module('apps.migrations.0056_mensagemprivada_chave_cifrada_v2')


class CifraV2Tests(TestCase):
    def test_ida_e_volta(self):
        for texto in ('', 'a', 'x' * 15, 'y' * 16, 'z' * 17, 'Olá, Recife! ☕ 漢字 🔐\n\x00fim'):
            chave = mc.gerar_chave()
            cifrado = mc.cifrar(texto, chave)
            self.assertEqual(mc.decifrar(cifrado, chave), texto)
            self.assertEqual(len(cifrado), mc.tamanho_cifrado(len(texto.encode('utf-8'))))

    def test_chave_dinamica_de_128_bits(self):
        chaves = {mc.gerar_chave() for _ in range(50)}
        self.assertEqual(len(chaves), 50)
        self.assertTrue(all(len(base64.urlsafe_b64decode(c)) == 16 for c in chaves))

    def test_iv_aleatorio(self):
        chave = mc.gerar_chave()
        self.assertNotEqual(mc.cifrar('mesmo texto', chave), mc.cifrar('mesmo texto', chave))

    def test_chave_errada_sempre_falha_e_e_registrada(self):
        cifrado = mc.cifrar('mensagem de teste', mc.gerar_chave())
        with self.assertLogs('security', level='WARNING'):
            for _ in range(50):
                with self.assertRaises(ValueError):
                    mc.decifrar(cifrado, mc.gerar_chave(), usuario='intruso')
        self.assertEqual(EventoSeguranca.objects.filter(tipo='falha_decifragem', usuario='intruso').count(), 50)

    def test_qualquer_alteracao_e_rejeitada(self):
        chave = mc.gerar_chave()
        bruto = base64.urlsafe_b64decode(mc.cifrar('Para 2 pessoas, sábado às 20h.', chave))
        with self.assertLogs('security', level='WARNING'):
            for i in range(len(bruto)):
                adulterado = bytearray(bruto)
                adulterado[i] ^= 1
                with self.subTest(byte=i), self.assertRaises(ValueError):
                    mc.decifrar(base64.urlsafe_b64encode(bytes(adulterado)).decode(), chave)

    def test_recusa_chave_da_v1(self):
        with self.assertRaises(ValueError):
            mc.cifrar('oi', v1.gerar_chave())

    def test_mistura_de_colunas_e_permutacao(self):
        # vetor de teste do MixColumns do AES: db 13 53 45 -> 8e 4d a1 bc
        self.assertEqual(mc._misturar_colunas(bytes.fromhex('db135345' * 4))[:4].hex(), '8e4da1bc')
        self.assertEqual(sorted(mc._PBOX), list(range(16)))
        for _ in range(100):
            bloco = os.urandom(16)
            self.assertEqual(mc._desmisturar_colunas(mc._misturar_colunas(bloco)), bloco)
            subchaves = mc._subchaves(os.urandom(16))
            self.assertEqual(mc._decifrar_bloco(mc._cifrar_bloco(bloco, subchaves), subchaves), bloco)

    def test_subchaves_independentes(self):
        subchaves = mc._subchaves(os.urandom(16))
        self.assertEqual(len(subchaves), mc.NUM_RODADAS + 1)
        self.assertEqual(len(set(subchaves)), mc.NUM_RODADAS + 1)
        self.assertTrue(all(len(s) == 16 for s in subchaves))


class MigracaoDaV1Tests(TestCase):
    def setUp(self):
        remetente = User.objects.create_user('ana', 'ana@example.com', 'SenhaForte@123')
        cafe = Cafe.objects.create(nome_cafeteria='Café Teste', cnpj='12345678901234')
        self.texto = 'Mensagem antiga: mesa para 4 no sábado.'
        self.chave_v1 = v1.gerar_chave()
        self.mensagem = MensagemPrivada.objects.create(remetente=remetente, cafe=cafe, texto_cifrado='x', chave='x')
        # Estado anterior à migration: texto na v1 e chave em claro na coluna.
        MensagemPrivada.objects.filter(pk=self.mensagem.pk).update(
            texto_cifrado=v1.cifrar(self.texto, self.chave_v1), chave=Value(self.chave_v1))

    def _chave_crua_no_banco(self):
        with connection.cursor() as cursor:
            cursor.execute('SELECT chave FROM apps_mensagemprivada WHERE id = %s', [self.mensagem.pk])
            return cursor.fetchone()[0]

    def test_migracao_recifra_e_esconde_a_chave_e_volta(self):
        with self.assertLogs('security', level='WARNING'), redirect_stdout(io.StringIO()):
            migracao.recifrar_para_v2(registro, None)  # avisa ao ler a chave legada em claro
        mensagem = MensagemPrivada.objects.get(pk=self.mensagem.pk)
        self.assertEqual(mensagem.texto_decifrado(), self.texto)
        self.assertEqual(len(base64.urlsafe_b64decode(mensagem.chave)), mc.TAMANHO_CHAVE)
        crua = self._chave_crua_no_banco()
        self.assertNotIn(mensagem.chave, crua)  # no banco só há o token Fernet
        self.assertNotEqual(crua, self.chave_v1)

        migracao.recifrar_para_v1(registro, None)
        crua = self._chave_crua_no_banco()
        texto_cifrado = MensagemPrivada.objects.filter(pk=self.mensagem.pk).values_list('texto_cifrado', flat=True)[0]
        self.assertEqual(v1.decifrar(texto_cifrado, crua), self.texto)

    def test_migrar_da_v1(self):
        cifrado, chave = mc.migrar_da_v1(v1.cifrar(self.texto, self.chave_v1), self.chave_v1)
        self.assertEqual(mc.decifrar(cifrado, chave), self.texto)
