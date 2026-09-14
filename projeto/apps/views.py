from django.shortcuts import render, redirect, get_object_or_404
from .models import *
from .models import Cafe, Avaliacao, UserCliente, Favorito
from datetime import datetime
from django.http import HttpResponseRedirect, Http404
from django.core.mail import send_mail
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.urls import reverse
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from django.contrib.auth.models import Group
from django.contrib.auth import logout as auth_logout
from django.utils import timezone
from django.db.models import Max
import json
import logging
import random
from django.http import JsonResponse
from .ai_moderation import classify_review

logger = logging.getLogger('security')

def home(request):
    cafes = Cafe.objects.all()
    favoritos = Favorito.objects.filter(usuario=request.user).values_list('cafe_id', flat=True) if request.user.is_authenticated else []
    context = {
        'cafes': cafes,
        'favoritos': list(favoritos),
    }
    for cafe in cafes:
        cafe.media_avaliacoes = cafe.media_avaliacoes()
        cafe.media_valor_gasto = cafe.media_valor_gasto()
    return render(request, 'home.html', context)


def buscar_cafeterias(request):
    if 'termo' in request.GET:
        termo = request.GET['termo']
        resultados = Cafe.objects.filter(Q(nome_cafeteria__icontains=termo) | Q(descricao__icontains=termo))
        if resultados:
            return render(request, 'resultado_busca.html', {'resultados': resultados, 'termo': termo})
        else:
            mensagem_alerta = f'Nenhuma cafeteria encontrada com o termo "{termo}".'
            return render(request, 'resultado_busca.html', {'mensagem_alerta': mensagem_alerta})
    else:
        return redirect('home')

@login_required
def cadastro_cafeteria(request):
    usuario = request.user
    email = usuario.email

    print(f"Conteúdo da sessão: {request.session.items()}")
    print(f"Usuário logado: {usuario.username}, ID: {usuario.id}")
    print(f"Grupos do usuário: {[group.name for group in usuario.groups.all()]}")

    is_empresario = usuario.groups.filter(name='Empresários').exists()
    print(f"Usuário é empresário: {is_empresario}")

    if not is_empresario:
        logger.warning(
            'Acesso negado: usuario=%s tentou cadastrar cafeteria sem ser empresario',
            usuario.username,
        )
        messages.error(request, 'Apenas empresários podem cadastrar cafeterias.')
        return redirect('acesso_negado_cadastrar_cafeteria')

    try:
        user_cliente = UserCliente.objects.get(user=usuario)
        print(f"UserCliente encontrado: {user_cliente}")
    except UserCliente.DoesNotExist:
        print("UserCliente não encontrado.")
        messages.error(request, 'Perfil de usuário não encontrado. Complete seu cadastro.')
        return redirect('cadastro_usuario')

    print(f"user_cliente.is_business: {user_cliente.is_business}")

    if request.method == 'POST':
        responsavel = request.POST.get('responsavel')
        nome_cafeteria = request.POST.get('nome_cafeteria')
        endereco = request.POST.get('endereco')
        descricao = request.POST.get('descricao')
        whatsapp = request.POST.get('whatsapp')
        horas_funcionamento = request.POST.get('horas_funcionamento')
        link_redesocial = request.POST.get('link_redesocial', '')
        cnpj = request.POST.get('cnpj')
        site_cafeteria = request.POST.get('site_cafeteria')

        if not whatsapp.isdigit() or len(whatsapp) != 13:
            return render(request, 'cadastro_cafeteria.html', {"erro": "O número de WhatsApp deve ter 13 dígitos."})

        if not cnpj.isdigit() or len(cnpj) != 14:
            return render(request, 'cadastro_cafeteria.html', {"erro": "O CNPJ deve conter apenas números e ter 14 dígitos."})

        if Cafe.objects.filter(whatsapp=whatsapp).exists():
            return render(request, 'cadastro_cafeteria.html', {"erro": "O número de WhatsApp já está em uso."})

        if Cafe.objects.filter(cnpj=cnpj).exists():
            return render(request, 'cadastro_cafeteria.html', {"erro": "O CNPJ já está em uso."})
        
        cafe = Cafe(
            responsavel=responsavel,
            nome_cafeteria=nome_cafeteria,
            endereco=endereco,
            descricao=descricao,
            email=email,
            whatsapp=whatsapp,
            horas_funcionamento=horas_funcionamento,
            link_redesocial=link_redesocial,
            cnpj=cnpj,
            site_cafeteria=site_cafeteria,
            empresario=user_cliente
        )

        if 'foto_ambiente' in request.FILES:
            cafe.foto_ambiente = request.FILES['foto_ambiente']

        cafe.full_clean()
        cafe.save()
        return redirect('cadastro_cafeteria_sucesso')

    return render(request, 'cadastro_cafeteria.html')

def cadastro_cafeteria_sucesso(request):
    return render(request, 'cadastro_cafeteria_sucesso.html')

def cadastro_user_sucesso(request):
    return render(request, 'cadastro_user_sucesso.html')

@login_required
def cancelar_reserva(request, reserva_id):
    reserva = get_object_or_404(ReservaCafe, id=reserva_id, cliente__email=request.user.email)

    if request.method == 'POST':
        reserva.delete()
        messages.success(request, 'Reserva cancelada com sucesso.')
        return redirect('minhas_reservas')
    
    return render(request, 'apps/cancelar_reserva.html', {'reserva': reserva})

@login_required
def criar_reserva(request, cafe_id):
    cafe = get_object_or_404(Cafe, id=cafe_id)
    cliente = get_object_or_404(UserCliente, email=request.user.email)
    
    if request.method == 'POST':
        nome_cliente = request.POST.get('nome_cliente')
        data_reserva = request.POST.get('data_reserva')
        horario_reserva = request.POST.get('horario_reserva')
        numero_de_pessoas = int(request.POST.get('numero_de_pessoas', 1))
        observacao = request.POST.get('observacao', '')

        if not nome_cliente or not data_reserva or not horario_reserva:
            return render(request, 'reservar_cafe.html', {
                'cafe': cafe,
                'error_message': 'Por favor, preencha todos os campos obrigatórios.'
            })

        try:
            data_reserva = datetime.strptime(data_reserva, '%Y-%m-%d').date()
            horario_reserva = datetime.strptime(horario_reserva, '%H:%M').time()
        except ValueError:
            return render(request, 'reservar_cafe.html', {
                'cafe': cafe,
                'error_message': 'Formato de data ou horário inválido.'
            })

        today_date = datetime.today().date()
        if data_reserva < today_date:
            return render(request, 'reservar_cafe.html', {
                'cafe': cafe,
                'error_message': 'A data selecionada deve ser futura.'
            })

        if numero_de_pessoas <= 0:
            return render(request, 'reservar_cafe.html', {
                'cafe': cafe,
                'error_message': 'O número de pessoas deve ser maior que zero.'
            })

        reservas_conflitantes = ReservaCafe.objects.filter(
            cafe=cafe,
            data_reserva=data_reserva,
            horario_reserva=horario_reserva
        )

        if reservas_conflitantes.exists():
            return render(request, 'reservar_cafe.html', {
                'cafe': cafe,
                'error_message': 'Café já reservado para o horário solicitado!'
            })

        reserva = ReservaCafe(
            cafe=cafe,
            cliente=cliente,
            nome_cliente=nome_cliente,
            data_reserva=data_reserva,
            horario_reserva=horario_reserva,
            numero_de_pessoas=numero_de_pessoas,
            observacao=observacao
        )
        reserva.save()
        
        messages.success(request, 'Reserva efetuada com sucesso.')
        return redirect('minhas_reservas')
    
    else:
        reservas = ReservaCafe.objects.filter(cafe=cafe).values('data_reserva', 'horario_reserva')
        horarios_reservados = {}
        for reserva in reservas:
            data_str = reserva['data_reserva'].strftime('%Y-%m-%d')
            horario_str = reserva['horario_reserva'].strftime('%H:%M')
            if data_str not in horarios_reservados:
                horarios_reservados[data_str] = []
            horarios_reservados[data_str].append(horario_str)

        return render(request, 'reservar_cafe.html', {
            'cafe': cafe,
            'horarios_reservados_json': json.dumps(horarios_reservados)
    })

def detalhes_anonimo(request, cafe_id):
        cafe = get_object_or_404(Cafe, id=cafe_id)
        detalhes_cafe = cafe.detalhes()

        outras_cafeterias = list(Cafe.objects.exclude(id=cafe_id))
        random.shuffle(outras_cafeterias)
        outras_cafeterias = outras_cafeterias[:4]

        return render(request, 'detalhes.html', {'cafe': cafe, 'detalhes_cafe': detalhes_cafe, 'outras_cafeterias': outras_cafeterias})

@login_required
def editar_reserva(request, reserva_id):
    # Autorização em nível de objeto: só o dono da reserva pode editá-la.
    try:
        reserva = get_object_or_404(ReservaCafe, id=reserva_id, cliente__email=request.user.email)
    except Http404:
        logger.warning(
            'Acesso negado: usuario=%s tentou editar reserva_id=%s que nao lhe pertence',
            request.user.username, reserva_id,
        )
        raise
    cafe = reserva.cafe
    
    if request.method == 'POST':
        nome_cliente = request.POST.get('nome_cliente')
        data_reserva = request.POST.get('data_reserva')
        horario_reserva = request.POST.get('horario_reserva')
        numero_de_pessoas = int(request.POST.get('numero_de_pessoas', 1))
        observacao = request.POST.get('observacao', '')

        if not nome_cliente or not data_reserva or not horario_reserva:
            return render(request, 'editar_reserva.html', {
                'reserva': reserva,  'cafe':cafe,
                'error_message': 'Por favor, preencha todos os campos obrigatórios.'
            })

        try:
            data_reserva = datetime.strptime(data_reserva, '%Y-%m-%d').date()
            horario_reserva = datetime.strptime(horario_reserva, '%H:%M').time()
        except ValueError:
            return render(request, 'editar_reserva.html', {
                'reserva': reserva, 'cafe':cafe,
                'error_message': 'Formato de data ou horário inválido.'
            })

        today_date = datetime.today().date()
        if data_reserva < today_date:
            return render(request, 'editar_reserva.html', {
                'reserva': reserva, 'cafe':cafe,
                'error_message': 'A data selecionada deve ser futura.'
            })

        if numero_de_pessoas <= 0:
            return render(request, 'editar_reserva.html', {
                'reserva': reserva, 'cafe':cafe,
                'error_message': 'O número de pessoas deve ser maior que zero.'
            })

        reservas_conflitantes = ReservaCafe.objects.filter(
            cafe=cafe,
            data_reserva=data_reserva,
            horario_reserva=horario_reserva
        ).exclude(id=reserva.id)

        if reservas_conflitantes.exists():
            return render(request, 'editar_reserva.html', {
                'reserva': reserva, 'cafe':cafe,
                'error_message': 'Café já reservado para o horário solicitado!'
            })

        reserva.data_reserva = data_reserva
        reserva.horario_reserva = horario_reserva
        reserva.numero_de_pessoas = numero_de_pessoas
        reserva.observacao = observacao
        reserva.save()
        
        messages.success(request, 'Reserva atualizada com sucesso.')
        return redirect('minhas_reservas')
    
    return render(request, 'editar_reserva.html', {
        'reserva': reserva, 'cafe':cafe
    })

@login_required
def enviar_whatsapp(request, cafe_id):
    cafeteria = get_object_or_404(Cafe, pk=cafe_id)
    if cafeteria.whatsapp:
        whatsapp_url = f"https://wa.me/{cafeteria.whatsapp}"
        return redirect(whatsapp_url)
    else:
        messages.error(request, "Número de WhatsApp não disponível.")
        return HttpResponseRedirect(reverse('perfil_cafeteria', args=[cafe_id]))

@login_required
def enviar_email(request, cafe_id):
    cafeteria = get_object_or_404(Cafe, pk=cafe_id)
    if request.method == 'POST':
        mensagem = request.POST.get('mensagem', '')
        send_mail(
            'Mensagem do MyCafeApp',
            mensagem,
            'from@example.com',
            [cafeteria.email],
            fail_silently=False,
        )
        messages.success(request, "Email enviado com sucesso!")
        return render(request, 'email_enviado.html', {'cafeteria': cafeteria})
    return render(request, 'enviar_email.html', {'cafeteria': cafeteria})

@login_required
def excluir_reserva(request, reserva_id):
    # Autorização em nível de objeto: só o dono da reserva pode excluí-la.
    try:
        reserva = get_object_or_404(ReservaCafe, id=reserva_id, cliente__email=request.user.email)
    except Http404:
        logger.warning(
            'Acesso negado: usuario=%s tentou excluir reserva_id=%s que nao lhe pertence',
            request.user.username, reserva_id,
        )
        raise
    
    if request.method == 'POST':
        reserva.delete()
        messages.success(request, 'Reserva excluída com sucesso.')
        return redirect('minhas_reservas')
    
    return render(request, 'excluir_reserva.html', {
        'reserva': reserva
    })

@login_required
def favoritar(request, cafe_id):
    cafe = get_object_or_404(Cafe, id=cafe_id)
    
    if request.method == 'POST' or request.method == 'GET':
        usuario = request.user
        
        favorito_existente = Favorito.objects.filter(usuario=usuario, cafe=cafe).exists()
        
        if not favorito_existente:
            Favorito.objects.create(usuario=usuario, cafe=cafe)
            status = 'favoritado'
            messages.success(request, 'Cafeteria favoritada com sucesso!')
        else:
            favorito = Favorito.objects.filter(usuario=usuario, cafe=cafe).first()
            favorito.delete()  # Remove o favorito se existir
            status = 'desfavoritado'
            messages.success(request, 'Cafeteria removida dos favoritos.')
        
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': status})
        
        return redirect('favoritos')
    
    return redirect('home')

@login_required
def lista_favoritos(request):
    if request.user.is_authenticated:
        favoritos = Favorito.objects.filter(usuario=request.user)
        return render(request, 'favoritos.html', {'favoritos': favoritos})
    else:
        return redirect('login')
    
@login_required
def registrar_historico(request, cafe_id): 
    cafe = get_object_or_404(Cafe, id=cafe_id)
    
    usuario = request.user
    # Evita múltiplas entradas no mesmo dia
    visita_hoje = Historico.objects.filter(usuario=usuario, cafe=cafe, visited_at__date=timezone.now().date()).exists()
    
    if not visita_hoje:
        Historico.objects.create(usuario=usuario, cafe=cafe)

    return redirect('cafe_detalhes', cafe_id=cafe.id)

@login_required
def lista_historico(request):
    if request.user.is_authenticated:
        historico = Historico.objects.filter(usuario=request.user).order_by('-visited_at')
        favoritos = Favorito.objects.filter(usuario=request.user).values_list('cafe_id', flat=True)
        return render(request, 'historico.html', {'historico': historico, 'favoritos': favoritos})
    else:
        return redirect('login')
    
@login_required
def detalhes(request, cafe_id):
    cafe = get_object_or_404(Cafe, id=cafe_id)
    media_avaliacoes = cafe.media_avaliacoes()
    media_valor_gasto = cafe.media_valor_gasto()
    range_5 = range(1, 6)
    usuario = request.user
    favorito = Favorito.objects.filter(usuario=usuario, cafe=cafe).exists()
    detalhes_cafe = cafe.detalhes()

    outras_cafeterias = list(Cafe.objects.exclude(id=cafe_id))
    for c in outras_cafeterias:
        c.media_avaliacoes = c.media_avaliacoes()
        media_valor_gasto = cafe.media_valor_gasto()
    random.shuffle(outras_cafeterias)
    outras_cafeterias = outras_cafeterias[:4]


    today = timezone.localdate()

    visita_hoje = Historico.objects.filter(
        usuario=usuario, 
        cafe=cafe, 
        visited_at__date=today,
    ).exists()

    if not visita_hoje:
        Historico.objects.create(usuario=usuario, cafe=cafe, visited_at=timezone.now())

    star_range = range(1, 6)

    return render(request, 'detalhes.html', {
        'cafe': cafe,
        'detalhes_cafe': detalhes_cafe,
        'favorito': favorito,
        'star_range': star_range,
        'range_5': range_5,
        'outras_cafeterias': outras_cafeterias,
        'media_avaliacoes': media_avaliacoes,
        'media_valor_gasto': media_valor_gasto,
    })
    
def limpar_historico_duplicado():
    # Encontrar a última visita para cada usuário e cafeteria por dia
    ultimas_visitas = Historico.objects.values('usuario_id', 'cafe_id', 'visited_at__date').annotate(
        ultima_visita=Max('visited_at')
    )

    # Converter resultados em uma lista de IDs de visitas para manter
    ids_para_manter = [visita['ultima_visita'] for visita in ultimas_visitas]

    # Excluir todas as visitas que não estão na lista de IDs para manter
    Historico.objects.exclude(id__in=ids_para_manter).delete()

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Mensagem única para e-mail inexistente E senha errada: não revela
        # quais e-mails estão cadastrados (anti-enumeração de usuários).
        credenciais_invalidas = 'E-mail ou senha inválidos.'

        ip = request.META.get('REMOTE_ADDR')

        try:
            username = User.objects.get(email=email).username
        except (ObjectDoesNotExist, User.MultipleObjectsReturned):
            logger.warning('Login falhou (email nao cadastrado): email=%s ip=%s', email, ip)
            return render(request, 'login.html', {'error': credenciais_invalidas})

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            logger.info('Login bem-sucedido: usuario=%s ip=%s', user.username, ip)
            if user.groups.filter(name='Empresários').exists():
                return redirect('cafeterias_empresarios')
            else:
                return redirect('home')
        else:
            logger.warning('Login falhou (senha incorreta): email=%s ip=%s', email, ip)
            return render(request, 'login.html', {'error': credenciais_invalidas})
        
    return render(request, 'login.html')

def logout(request):
    auth_logout(request)
    if "usuario" in request.session:
        del request.session["usuario"]
    request.session.flush()
    return redirect('home')

@login_required
def minhas_reservas(request):
    try:
        cliente = UserCliente.objects.get(email=request.user.email)
    except UserCliente.DoesNotExist:
        return redirect('login')

    reservas = ReservaCafe.objects.filter(cliente=cliente)
    return render(request, 'minhas_reservas.html', {'reservas': reservas})

def api_cafeterias(request):
    cafes = Cafe.objects.all().values(
        'id', 'nome_cafeteria', 'endereco', 'descricao', 'horas_funcionamento'
    )
    return JsonResponse({'cafeterias': list(cafes)})

@login_required
def api_minhas_reservas(request):
    # Mesmo filtro por dono usado em editar_reserva/excluir_reserva: cada
    # usuário só enxerga as próprias reservas, nunca as de terceiros.
    reservas = ReservaCafe.objects.filter(cliente__email=request.user.email).values(
        'id', 'cafe__nome_cafeteria', 'data_reserva', 'horario_reserva', 'numero_de_pessoas'
    )
    return JsonResponse({'reservas': list(reservas)})

def perfil_cafeteria(request, cafe_id):
    cafeteria = get_object_or_404(Cafe, pk=cafe_id)
    return render(request, 'perfil_cafeteria.html', {'cafeteria': cafeteria})

def UserCadastro(request):
    if request.method == 'POST':
        username = request.POST['username']
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST.get('confirm_password')
        is_business = request.POST.get('is_business') == 'on'

        if password != confirm_password:
                messages.error(request, 'As senhas não correspondem.')
                return render(request, 'cadastro_usuario.html', {'form': request.POST})
        
        if User.objects.filter(username=username).exists():
            return render(request, 'cadastro_usuario.html', {"erro": "Usuário já existe"})
        if User.objects.filter(email=email).exists():
            return render(request, 'cadastro_usuario.html', {"erro": "Email já cadastrado"})

        user = User.objects.create_user(username=username, password=password, email=email, first_name=name)

        if is_business:
            empresario_group, _ = Group.objects.get_or_create(name='Empresários')
            user.groups.add(empresario_group)

        user_cliente = UserCliente(user=user, nome_completo=name, email=email, is_business=is_business)
        user_cliente.save()

        login(request, user)
        request.session["usuario"] = email

        print(f"Usuário {username} criado com is_business={is_business}")

        if is_business:
            return redirect('cadastro_empresario_sucesso') 
        else:
            return redirect('cadastro_user_sucesso')
        
    return render(request, 'cadastro_usuario.html')

@login_required
def cadastro_empresario_sucesso(request):
    return render(request, 'cadastro_empresario_sucesso.html')

@login_required
def cafeterias_empresarios(request):
    usuario = request.user
    empresaario = usuario.usercliente
    cafeterias = Cafe.objects.filter(empresario=empresaario)
    return render(request, 'cafeterias_empresarios.html', {'cafeterias': cafeterias})

@login_required
def home_empresario(request):
    return render(request, 'cafeterias_empresarios.html')

def acesso_negado_cadastrar_cafeteria(request):
    return render(request, 'acesso_negado_cadastrar_cafeteria.html')

@login_required
def avaliar_cafe(request, cafe_id):
    cafe = get_object_or_404(Cafe, id=cafe_id)
    try:
        cliente = get_object_or_404(UserCliente, user=request.user)
    except UserCliente.DoesNotExist:
        messages.error(request, 'Perfil de usuário não encontrado. Complete seu cadastro.')
        return redirect('cadastro_usuario')

    if request.method == 'POST':
        avaliacao = request.POST.get('avaliacao')
        comentario = request.POST.get('comentario')
        valor_gasto = request.POST.get('valor_gasto')
        foto_experiencia = request.FILES.get('foto_experiencia')

        if not avaliacao or not comentario or not valor_gasto:
            messages.error(request, 'Por favor, preencha todos os campos obrigatórios.')
            return render(request, 'avaliar_cafe.html', {'cafe': cafe, 'range': range(1, 6)})

        resultado_ia = classify_review(comentario, cliente_email=cliente.email)

        Avaliacao.objects.create(
            cafe=cafe,
            cliente=cliente,
            avaliacao=int(avaliacao),
            comentario=comentario,
            valor_gasto=valor_gasto,
            foto_avaliacao=foto_experiencia,
            classificacao_ia=resultado_ia.status,
            justificativa_ia=resultado_ia.raw_response,
        )

        if resultado_ia.status == 'rejeitado':
            messages.warning(
                request,
                'Sua avaliação foi enviada, mas ficou retida pela moderação automática '
                'e não aparecerá publicamente até revisão.'
            )
        elif resultado_ia.status == 'pendente':
            messages.info(
                request,
                'Sua avaliação foi enviada e está aguardando moderação.'
            )
        else:
            messages.success(request, 'Avaliação enviada com sucesso.')
        return redirect('avaliacao_sucesso')

    return render(request, 'avaliar_cafe.html', {'cafe': cafe, 'range': range(1, 6)})

@login_required
def avaliacao_sucesso(request):
    return render(request, 'avaliacao_sucesso.html')

@login_required
def perfil_usuario(request):
    user_cliente = UserCliente.objects.get(user=request.user)
    print(f"Tipo de Usuário: {user_cliente.is_business}")
    context = {
        'user_cliente': user_cliente
    }
    return render(request, 'perfil_usuario.html', context)

@login_required
def editar_perfil(request):
    user_cliente = UserCliente.objects.get(user=request.user)
    if request.method == 'POST':
        username = request.POST.get('username')
        nome_completo = request.POST.get('nome_completo')
        email = request.POST.get('email')
        profile_image = request.FILES.get('profile_image')

        if not username:
            username = user_cliente.user.username
        if not nome_completo:
            nome_completo = user_cliente.nome_completo
        if not email:
            email = user_cliente.email

        if UserCliente.objects.filter(email=email).exclude(id=user_cliente.id).exists():
            return render(request, 'editar_perfil.html', {
                'error': 'Este email já está em uso por outro usuário.',
                'user_cliente': user_cliente
            })

        if User.objects.filter(username=username).exclude(id=user_cliente.user.id).exists():
            return render(request, 'editar_perfil.html', {
                'error': 'Este username já está em uso por outro usuário.',
                'user_cliente': user_cliente
            })

        user_cliente.user.username = username
        user_cliente.user.save()
        user_cliente.nome_completo = nome_completo
        user_cliente.email = email

        if profile_image:
            # Atribui o arquivo enviado diretamente (em vez de salvar manualmente
            # via FileSystemStorage) para que o ImageField use o upload_to correto
            # e o hash SHA-256 de integridade seja calculado em UserCliente.save().
            user_cliente.profile_image = profile_image

        user_cliente.save()

        return redirect('editar_perfil_sucesso')
    else:
        return render(request, 'editar_perfil.html', {'user_cliente': user_cliente})

def editar_perfil_sucesso(request):
    return render(request, 'editar_perfil_sucesso.html')

@login_required
def editar_cadastro_cafe(request, cafe_id):
    # Obter o UserCliente associado ao usuário logado
    user_cliente = request.user.usercliente
    
    # Obter a cafeteria específica associada ao UserCliente
    cafe = get_object_or_404(Cafe, id=cafe_id, empresario=user_cliente)
    
    if request.method == 'POST':
        responsavel = request.POST.get('responsavel') or cafe.responsavel
        nome_cafeteria = request.POST.get('nome_cafeteria') or cafe.nome_cafeteria
        endereco = request.POST.get('endereco') or cafe.endereco
        descricao = request.POST.get('descricao') or cafe.descricao
        email = request.POST.get('email') or cafe.email
        whatsapp = request.POST.get('whatsapp') or cafe.whatsapp
        horas_funcionamento = request.POST.get('horas_funcionamento') or cafe.horas_funcionamento
        link_redesocial = request.POST.get('link_redesocial') or cafe.link_redesocial
        foto_ambiente = request.FILES.get('foto_ambiente') or cafe.foto_ambiente
        cnpj = request.POST.get('cnpj') or cafe.cnpj
        site_cafeteria = request.POST.get('site_cafeteria') or cafe.site_cafeteria

        if not whatsapp.isdigit() or len(whatsapp) != 13:
            return render(request, 'editar_cadastro_cafe.html', {
                'erro': 'O número de WhatsApp deve conter apenas números e ter 13 dígitos.',
                'cafe': cafe
            })

        if not cnpj.isdigit() or len(cnpj) != 14:
            return render(request, 'editar_cadastro_cafe.htmll', {
                'erro': 'O CNPJ deve conter apenas números e ter 14 dígitos.',
                'cafe': cafe
            })
        
        if Cafe.objects.filter(cnpj=cnpj).exclude(pk=cafe.pk).exists():
            return render(request, 'editar_cadastro_cafe.html', {
                'erro': 'Este CNPJ já está em uso por outra cafeteria.',
                'cafe': cafe
            })
        
        if Cafe.objects.filter(whatsapp=whatsapp).exclude(pk=cafe.pk).exists():
            return render(request, 'editar_cadastro_cafe.html', {
                'erro': 'Este Whatsapp já está em uso por outra cafeteria.',
                'cafe': cafe
            })

        cafe.responsavel = responsavel
        cafe.nome_cafeteria = nome_cafeteria
        cafe.endereco = endereco
        cafe.descricao = descricao
        cafe.email = email
        cafe.whatsapp = whatsapp
        cafe.horas_funcionamento = horas_funcionamento
        cafe.link_redesocial = link_redesocial
        cafe.foto_ambiente = foto_ambiente
        cafe.cnpj = cnpj
        cafe.site_cafeteria = site_cafeteria
        
        cafe.save()

        return redirect('editar_cadastro_cafeteria_sucesso')
    
    return render(request, 'editar_cadastro_cafe.html', {
        'cafe': cafe
    })

def editar_cadastro_cafeteria_sucesso(request):
    return render(request, 'editar_cadastro_cafeteria_sucesso.html')

