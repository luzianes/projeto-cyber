from datetime import time, timedelta

from django.conf import settings
from django.contrib.auth.models import Group, User
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.models import Avaliacao, Cafe, Favorito, Historico, ReservaCafe, UserCliente


PASSWORD = "Aponte123!"
EMPRESARIOS_GROUP = "Empres\u00e1rios"

USERS = [
    {
        "username": "maria_julia",
        "email": "maria.julia@apontecafes.local",
        "name": "Maria Julia",
        "business": False,
        "staff": True,
        "superuser": True,
    },
    {
        "username": "lia_monteiro",
        "email": "lia.monteiro@apontecafes.local",
        "name": "Lia Monteiro",
        "business": True,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "roberto_alves",
        "email": "roberto.alves@apontecafes.local",
        "name": "Roberto Alves",
        "business": True,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "ana_bezerra",
        "email": "ana.bezerra@apontecafes.local",
        "name": "Ana Bezerra",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "bruno_lima",
        "email": "bruno.lima@apontecafes.local",
        "name": "Bruno Lima",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "carla_souza",
        "email": "carla.souza@apontecafes.local",
        "name": "Carla Souza",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "diego_nunes",
        "email": "diego.nunes@apontecafes.local",
        "name": "Diego Nunes",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "eduarda_melo",
        "email": "eduarda.melo@apontecafes.local",
        "name": "Eduarda Melo",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "felipe_rocha",
        "email": "felipe.rocha@apontecafes.local",
        "name": "Felipe Rocha",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "gabi_martins",
        "email": "gabi.martins@apontecafes.local",
        "name": "Gabi Martins",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "henrique_barros",
        "email": "henrique.barros@apontecafes.local",
        "name": "Henrique Barros",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "isabela_costa",
        "email": "isabela.costa@apontecafes.local",
        "name": "Isabela Costa",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "joao_ferreira",
        "email": "joao.ferreira@apontecafes.local",
        "name": "Joao Ferreira",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "karina_gomes",
        "email": "karina.gomes@apontecafes.local",
        "name": "Karina Gomes",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "lucas_araujo",
        "email": "lucas.araujo@apontecafes.local",
        "name": "Lucas Araujo",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "marina_duarte",
        "email": "marina.duarte@apontecafes.local",
        "name": "Marina Duarte",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "nicolas_freitas",
        "email": "nicolas.freitas@apontecafes.local",
        "name": "Nicolas Freitas",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "olivia_torres",
        "email": "olivia.torres@apontecafes.local",
        "name": "Olivia Torres",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "paulo_mendes",
        "email": "paulo.mendes@apontecafes.local",
        "name": "Paulo Mendes",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "quiteria_ramos",
        "email": "quiteria.ramos@apontecafes.local",
        "name": "Quiteria Ramos",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "rafaela_castro",
        "email": "rafaela.castro@apontecafes.local",
        "name": "Rafaela Castro",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "samuel_correia",
        "email": "samuel.correia@apontecafes.local",
        "name": "Samuel Correia",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "talita_andrade",
        "email": "talita.andrade@apontecafes.local",
        "name": "Talita Andrade",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "ulisses_cardoso",
        "email": "ulisses.cardoso@apontecafes.local",
        "name": "Ulisses Cardoso",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "valeria_farias",
        "email": "valeria.farias@apontecafes.local",
        "name": "Valeria Farias",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "william_pereira",
        "email": "william.pereira@apontecafes.local",
        "name": "William Pereira",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "yasmin_teixeira",
        "email": "yasmin.teixeira@apontecafes.local",
        "name": "Yasmin Teixeira",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "zoe_matos",
        "email": "zoe.matos@apontecafes.local",
        "name": "Zoe Matos",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "miguel_campos",
        "email": "miguel.campos@apontecafes.local",
        "name": "Miguel Campos",
        "business": False,
        "staff": False,
        "superuser": False,
    },
    {
        "username": "sofia_ribeiro",
        "email": "sofia.ribeiro@apontecafes.local",
        "name": "Sofia Ribeiro",
        "business": False,
        "staff": False,
        "superuser": False,
    },
]

LEGACY_USERNAMES = [
    "admin_fake",
    "maju",
    "barista_lia",
    "roberto_cafe",
    "ana_cliente",
    "bruno_cliente",
    "carla_cliente",
    "diego_cliente",
    "eduarda_cliente",
    "felipe_cliente",
    "gabi_cliente",
    "henrique_cliente",
    "isabela_cliente",
    "joao_cliente",
    "karina_cliente",
    "lucas_cliente",
    "marina_cliente",
    "nicolas_cliente",
    "olivia_cliente",
    "paulo_cliente",
    "quiteria_cliente",
    "rafaela_cliente",
    "samuel_cliente",
    "talita_cliente",
    "ulisses_cliente",
    "valeria_cliente",
    "william_cliente",
    "yasmin_cliente",
    "zoe_cliente",
    "miguel_cliente",
    "sofia_cliente",
]

LEGACY_EMAILS = [
    "admin.fake@apontecafes.local",
    "maju@apontecafes.local",
    "lia.empresaria@apontecafes.local",
    "roberto.empresario@apontecafes.local",
    "ana.cliente@apontecafes.local",
    "bruno.cliente@apontecafes.local",
    "carla.cliente@apontecafes.local",
    "diego.cliente@apontecafes.local",
    "eduarda.cliente@apontecafes.local",
    "felipe.cliente@apontecafes.local",
    "gabi.cliente@apontecafes.local",
    "henrique.cliente@apontecafes.local",
    "isabela.cliente@apontecafes.local",
    "joao.cliente@apontecafes.local",
    "karina.cliente@apontecafes.local",
    "lucas.cliente@apontecafes.local",
    "marina.cliente@apontecafes.local",
    "nicolas.cliente@apontecafes.local",
    "olivia.cliente@apontecafes.local",
    "paulo.cliente@apontecafes.local",
    "quiteria.cliente@apontecafes.local",
    "rafaela.cliente@apontecafes.local",
    "samuel.cliente@apontecafes.local",
    "talita.cliente@apontecafes.local",
    "ulisses.cliente@apontecafes.local",
    "valeria.cliente@apontecafes.local",
    "william.cliente@apontecafes.local",
    "yasmin.cliente@apontecafes.local",
    "zoe.cliente@apontecafes.local",
    "miguel.cliente@apontecafes.local",
    "sofia.cliente@apontecafes.local",
]

CAFES = [
    {
        "owner": "lia_monteiro",
        "responsavel": "Lia Monteiro",
        "nome_cafeteria": "Cafe Marco Zero",
        "endereco": "Av. Alfredo Lisboa, 10 - Recife Antigo, Recife",
        "descricao": "Cafeteria urbana com graos especiais, mesas compartilhadas e vista para o Recife Antigo.",
        "email": "contato@cafemarcozero.local",
        "whatsapp": "5581999000001",
        "horas_funcionamento": "Seg a sex, 8h as 19h; sab, 9h as 16h",
        "link_redesocial": "https://instagram.com/cafemarcozero",
        "cnpj": "10000000000101",
        "site_cafeteria": "https://cafemarcozero.local",
    },
    {
        "owner": "lia_monteiro",
        "responsavel": "Lia Monteiro",
        "nome_cafeteria": "Grao do Patio",
        "endereco": "Rua do Bom Jesus, 84 - Recife Antigo, Recife",
        "descricao": "Espaco pequeno e aconchegante para espresso, paes artesanais e leitura no fim da tarde.",
        "email": "ola@graodopatio.local",
        "whatsapp": "5581999000002",
        "horas_funcionamento": "Todos os dias, 7h30 as 20h",
        "link_redesocial": "https://instagram.com/graodopatio",
        "cnpj": "10000000000102",
        "site_cafeteria": "https://graodopatio.local",
    },
    {
        "owner": "lia_monteiro",
        "responsavel": "Lia Monteiro",
        "nome_cafeteria": "Torra da Rua",
        "endereco": "Rua da Moeda, 42 - Recife Antigo, Recife",
        "descricao": "Torrefacao experimental com metodos filtrados, cold brew e doces regionais.",
        "email": "contato@torradarua.local",
        "whatsapp": "5581999000003",
        "horas_funcionamento": "Ter a dom, 10h as 21h",
        "link_redesocial": "https://instagram.com/torradarua",
        "cnpj": "10000000000103",
        "site_cafeteria": "https://torradarua.local",
    },
    {
        "owner": "roberto_alves",
        "responsavel": "Roberto Alves",
        "nome_cafeteria": "Capibaribe Coffee",
        "endereco": "Rua Madre de Deus, 155 - Recife Antigo, Recife",
        "descricao": "Cardapio com cafe coado na mesa, brunch simples e tomadas perto das bancadas.",
        "email": "contato@capibaribecoffee.local",
        "whatsapp": "5581999000004",
        "horas_funcionamento": "Seg a sab, 8h as 18h",
        "link_redesocial": "https://instagram.com/capibaribecoffee",
        "cnpj": "10000000000104",
        "site_cafeteria": "https://capibaribecoffee.local",
    },
    {
        "owner": "roberto_alves",
        "responsavel": "Roberto Alves",
        "nome_cafeteria": "Bule da Aurora",
        "endereco": "Rua da Aurora, 320 - Boa Vista, Recife",
        "descricao": "Casa clara com varanda, cappuccino cremoso e opcoes para reunioes pequenas.",
        "email": "reservas@buledaaurora.local",
        "whatsapp": "5581999000005",
        "horas_funcionamento": "Seg a sex, 7h as 18h",
        "link_redesocial": "https://instagram.com/buledaaurora",
        "cnpj": "10000000000105",
        "site_cafeteria": "https://buledaaurora.local",
    },
    {
        "owner": "roberto_alves",
        "responsavel": "Roberto Alves",
        "nome_cafeteria": "Estacao Espresso",
        "endereco": "Av. Conde da Boa Vista, 700 - Boa Vista, Recife",
        "descricao": "Ponto rapido perto do centro, com espresso, sanduiches e combos para viagem.",
        "email": "contato@estacaoespresso.local",
        "whatsapp": "5581999000006",
        "horas_funcionamento": "Seg a sex, 6h30 as 19h; sab, 8h as 14h",
        "link_redesocial": "https://instagram.com/estacaoespresso",
        "cnpj": "10000000000106",
        "site_cafeteria": "https://estacaoespresso.local",
    },
]

REVIEWS = [
    ("ana_bezerra", "10000000000101", 5, "Cafe muito bem extraido e atendimento rapido.", "20-40", "aprovado"),
    ("bruno_lima", "10000000000101", 4, "Bom para trabalhar de manha, so fica cheio perto do almoco.", "40-60", "aprovado"),
    ("carla_souza", "10000000000102", 5, "O bolo de rolo combina muito bem com o filtrado da casa.", "20-40", "aprovado"),
    ("diego_nunes", "10000000000103", 3, "Gostei dos metodos, mas achei o ambiente um pouco barulhento.", "60-80", "aprovado"),
    ("ana_bezerra", "10000000000104", 4, "Tomadas funcionando e wifi estavel para reunioes curtas.", "40-60", "aprovado"),
    ("bruno_lima", "10000000000105", 5, "Varanda agradavel e cappuccino excelente.", "20-40", "aprovado"),
    ("carla_souza", "10000000000106", 4, "Boa opcao para pegar cafe antes da aula.", "1-20", "aprovado"),
    ("diego_nunes", "10000000000102", 2, "Comentario retido para simular revisao manual.", "20-40", "pendente"),
]

FAVORITES = [
    ("ana_bezerra", "10000000000101"),
    ("ana_bezerra", "10000000000104"),
    ("bruno_lima", "10000000000105"),
    ("carla_souza", "10000000000102"),
    ("diego_nunes", "10000000000103"),
]

HISTORY = [
    ("ana_bezerra", "10000000000101"),
    ("ana_bezerra", "10000000000102"),
    ("bruno_lima", "10000000000105"),
    ("carla_souza", "10000000000106"),
    ("diego_nunes", "10000000000103"),
]

RESERVATIONS = [
    ("ana_bezerra", "10000000000101", 1, time(9, 30), 2, "Mesa perto da janela."),
    ("bruno_lima", "10000000000105", 2, time(15, 0), 4, "Aniversario pequeno."),
    ("carla_souza", "10000000000102", 3, time(10, 0), 1, "Preferencia por area tranquila."),
    ("diego_nunes", "10000000000103", 5, time(17, 30), 3, "Experimentar metodos filtrados."),
]


class Command(BaseCommand):
    help = "Popula o banco local com dados ficticios para desenvolvimento."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Remove os dados ficticios antes de recria-los.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if not getattr(settings, "FIELD_ENCRYPTION_KEY", ""):
            raise CommandError(
                "FIELD_ENCRYPTION_KEY nao configurada. Defina a chave em projeto.env antes de criar reservas."
            )

        if options["reset"]:
            self._reset_seed_data()

        group, _ = Group.objects.get_or_create(name=EMPRESARIOS_GROUP)
        users, profiles = self._upsert_users(group)
        cafes = self._upsert_cafes(profiles)

        self._clear_seed_relations()
        self._create_reviews(profiles, cafes)
        self._create_favorites(users, cafes)
        self._create_history(users, cafes)
        self._create_reservations(profiles, cafes)

        self.stdout.write(self.style.SUCCESS("Banco ficticio criado com sucesso."))
        self.stdout.write(f"Usuarios fake: {len(users)} | Cafeterias: {len(cafes)} | Senha padrao: {PASSWORD}")

    def _upsert_users(self, group):
        users = {}
        profiles = {}

        for data in USERS:
            user, _ = User.objects.get_or_create(username=data["username"])
            user.email = data["email"]
            user.first_name = data["name"]
            user.is_active = True
            user.is_staff = data["staff"]
            user.is_superuser = data["superuser"]
            user.set_password(PASSWORD)
            user.save()

            if data["business"]:
                user.groups.add(group)
            else:
                user.groups.remove(group)

            UserCliente.objects.filter(email=data["email"]).exclude(user=user).delete()
            profile, _ = UserCliente.objects.update_or_create(
                user=user,
                defaults={
                    "nome_completo": data["name"],
                    "email": data["email"],
                    "is_business": data["business"],
                },
            )

            users[data["username"]] = user
            profiles[data["username"]] = profile

        return users, profiles

    def _upsert_cafes(self, profiles):
        cafes = {}

        for data in CAFES:
            owner = profiles[data["owner"]]
            cafe, _ = Cafe.objects.update_or_create(
                cnpj=data["cnpj"],
                defaults={
                    "responsavel": data["responsavel"],
                    "nome_cafeteria": data["nome_cafeteria"],
                    "endereco": data["endereco"],
                    "descricao": data["descricao"],
                    "email": data["email"],
                    "whatsapp": data["whatsapp"],
                    "horas_funcionamento": data["horas_funcionamento"],
                    "link_redesocial": data["link_redesocial"],
                    "site_cafeteria": data["site_cafeteria"],
                    "empresario": owner,
                },
            )
            cafes[data["cnpj"]] = cafe

        return cafes

    def _create_reviews(self, profiles, cafes):
        for username, cnpj, nota, comentario, valor_gasto, status in REVIEWS:
            Avaliacao.objects.create(
                cafe=cafes[cnpj],
                cliente=profiles[username],
                avaliacao=nota,
                comentario=comentario,
                valor_gasto=valor_gasto,
                classificacao_ia=status,
                justificativa_ia=f"Seed fake: {status}",
            )

    def _create_favorites(self, users, cafes):
        for username, cnpj in FAVORITES:
            Favorito.objects.create(usuario=users[username], cafe=cafes[cnpj])

    def _create_history(self, users, cafes):
        for username, cnpj in HISTORY:
            Historico.objects.create(usuario=users[username], cafe=cafes[cnpj])

    def _create_reservations(self, profiles, cafes):
        today = timezone.localdate()

        for username, cnpj, days_from_today, reservation_time, people, note in RESERVATIONS:
            ReservaCafe.objects.create(
                cafe=cafes[cnpj],
                cliente=profiles[username],
                nome_cliente=profiles[username].nome_completo,
                data_reserva=today + timedelta(days=days_from_today),
                horario_reserva=reservation_time,
                numero_de_pessoas=people,
                observacao=note,
            )

    def _clear_seed_relations(self):
        seed_usernames = [user["username"] for user in USERS] + LEGACY_USERNAMES
        seed_emails = [user["email"] for user in USERS] + LEGACY_EMAILS
        seed_cnpjs = [cafe["cnpj"] for cafe in CAFES]

        ReservaCafe.objects.filter(cliente__email__in=seed_emails, cafe__cnpj__in=seed_cnpjs).delete()
        Avaliacao.objects.filter(cliente__email__in=seed_emails, cafe__cnpj__in=seed_cnpjs).delete()
        Favorito.objects.filter(usuario__username__in=seed_usernames, cafe__cnpj__in=seed_cnpjs).delete()
        Historico.objects.filter(usuario__username__in=seed_usernames, cafe__cnpj__in=seed_cnpjs).delete()

    def _reset_seed_data(self):
        self._clear_seed_relations()
        seed_emails = [user["email"] for user in USERS] + LEGACY_EMAILS
        seed_usernames = [user["username"] for user in USERS] + LEGACY_USERNAMES
        seed_cnpjs = [cafe["cnpj"] for cafe in CAFES]

        Cafe.objects.filter(cnpj__in=seed_cnpjs).delete()
        UserCliente.objects.filter(email__in=seed_emails).delete()
        User.objects.filter(username__in=seed_usernames).delete()
