# -*- coding: utf-8 -*-
"""
Url patterns for VDI project (Django)
"""
from django.conf.urls import include
from django.urls import path


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()


urlpatterns = [
    path('', include('vdi.urls')),
]
