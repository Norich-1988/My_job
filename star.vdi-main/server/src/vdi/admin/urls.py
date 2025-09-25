from __future__ import unicode_literals
from django.urls import re_path

import vdi.admin.views

__updated__ = '2019-02-04'

urlpatterns = [
    re_path(r'^.*$', vdi.admin.views.index, name='vdi.admin.views.index'),
]
