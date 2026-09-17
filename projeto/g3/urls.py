"""
URL configuration for g3 project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.views.static import serve


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.urls')),
    path('apps/', include(('apps.urls', 'apps'), namespace='projeto/apps')),
    # Servido incondicionalmente (nao so quando DEBUG=True) para que uploads
    # funcionem com DEBUG=0. Para producao de verdade, o ideal e um proxy
    # (Nginx) ou storage externo (S3) servindo /media/ em vez do Django.
    re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
]
