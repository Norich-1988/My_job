import logging

from django.http import HttpResponse
from django.middleware import csrf
from django.shortcuts import render
from django.template import RequestContext, loader
from django.utils.translation import gettext as _

from vdi.core.auths.auth import webLoginRequired
from vdi.core.util.decorators import denyBrowsers

logger = logging.getLogger(__name__)


CSRF_FIELD = 'csrfmiddlewaretoken'


@denyBrowsers(browsers=['ie<10'])
@webLoginRequired(admin=True)
def index(request):
    # Gets csrf token
    csrf_token = csrf.get_token(request)
    if csrf_token is not None:
        csrf_token = str(csrf_token)

    return render(
        request,
        'vdi/admin/index.html',
        {'csrf_field': CSRF_FIELD, 'csrf_token': csrf_token},
    )


@denyBrowsers(browsers=['ie<10'])
@webLoginRequired(admin=True)
def tmpl(request, template):
    try:
        t = loader.get_template('vdi/admin/tmpl/' + template + ".html")
        c = RequestContext(request)
        resp = t.render(c.flatten())
    except Exception as e:
        logger.debug('Exception getting template: %s', e)
        resp = _('requested a template that do not exist')
    return HttpResponse(resp, content_type="text/plain")


@denyBrowsers(browsers=['ie<10'])
@webLoginRequired(admin=True)
def sample(request):
    return render(request, 'vdi/admin/sample.html')
