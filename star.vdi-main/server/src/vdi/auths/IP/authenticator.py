import logging
import typing

from django.utils.translation import gettext_noop as _
from vdi.core import auths
from vdi.core.util import net
from vdi.core.ui import gui
from vdi.core.util.request import getRequest, ExtendedHttpRequest

logger = logging.getLogger(__name__)


class IPAuth(auths.Authenticator):
    acceptProxy = gui.CheckBoxField(
        label=_('Accept proxy'),
        defvalue=gui.FALSE,
        order=50,
        tooltip=_(
            'If checked, requests via proxy will get FORWARDED ip address'
            ' (take care with this bein checked, can take internal IP addresses from internet)'
        ),
        tab=gui.ADVANCED_TAB
    )

    visibleFromNets = gui.TextField(
        order=50,
        label=_('Visible only from this networks'),
        defvalue='',
        tooltip=_('This authenticator will be visible only from these networks. Leave empty to allow all networks'),
        tab=gui.ADVANCED_TAB
    )

    typeName = _('IP Authenticator')
    typeType = 'IPAuth'
    typeDescription = _('IP Authenticator')
    iconFile = 'auth.png'

    needsPassword = False
    userNameLabel = _('IP')
    groupNameLabel = _('IP Range')
    isExternalSource = True

    blockUserOnLoginFailures = False

    def getIp(self) -> str:
        ip = getRequest().ip_proxy if self.acceptProxy.isTrue() else getRequest().ip
        logger.debug('Client IP: %s', ip)
        return ip

    def getGroups(self, username: str, groupsManager: 'auths.GroupsManager'):
        # these groups are a bit special. They are in fact ip-ranges, and we must check that the ip is in betwen
        # The ranges are stored in group names
        for g in groupsManager.getGroupsNames():
            try:
                if net.ipInNetwork(username, g):
                    groupsManager.validate(g)
            except Exception as e:
                logger.error('Invalid network for IP auth: %s', e)

    def authenticate(self, username: str, credentials: str, groupsManager: 'auths.GroupsManager') -> bool:
        # If credentials is a dict, that can't be sent directly from web interface, we allow entering
        if username == self.getIp():
            self.getGroups(username, groupsManager)
            return True
        return False

    def isVisibleFrom(self, request: 'ExtendedHttpRequest'):
        """
        Used by the login interface to determine if the authenticator is visible on the login page.
        """
        validNets = self.visibleFromNets.value.strip()
        try:
            if not validNets or net.ipInNetwork(request.ip, validNets):
                return True
        except Exception as e:
            logger.error('Invalid network for IP auth: %s', e)
        return False

    def internalAuthenticate(self, username: str, credentials: str, groupsManager: 'auths.GroupsManager') -> bool:
        # In fact, username does not matter, will get IP from request
        username = self.getIp()  # Override provided username and use source IP
        self.getGroups(username, groupsManager)
        if groupsManager.hasValidGroups() and self.dbAuthenticator().isValidUser(username, True):
            return True
        return False

    @staticmethod
    def test(env, data):
        return _("All seems to be fine.")

    def check(self):
        return _("All seems to be fine.")

    def getJavascript(self, request: 'ExtendedHttpRequest') -> typing.Optional[str]:
        # We will authenticate ip here, from request.ip
        # If valid, it will simply submit form with ip submited and a cached generated random password
        ip = self.getIp()
        gm = auths.GroupsManager(self.dbAuthenticator())
        self.getGroups(ip, gm)

        if gm.hasValidGroups() and self.dbAuthenticator().isValidUser(ip, True):
            return '''function setVal(element, value) {{
                        document.getElementById(element).value = value;
                    }}
                    setVal("id_user", "{ip}");
                    setVal("id_password", "{passwd}");
                    document.getElementById("loginform").submit();'''.format(ip=ip, passwd='')

        return 'alert("invalid authhenticator"); window.location.reload();'

    def __str__(self):
        return "IP Authenticator"
