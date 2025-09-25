import logging
import typing

import dns.resolver
import dns.reversename

from django.utils.translation import gettext_noop as _
from vdi.core import auths
from vdi.core.ui import gui
from vdi.core.managers import cryptoManager
from vdi.core.util.state import State
from vdi.core.util.request import getRequest
from vdi.core.auths.auth import authLogLogin

# Not imported at runtime, just for type checking
if typing.TYPE_CHECKING:
    from vdi import models

logger = logging.getLogger(__name__)


class InternalDBAuth(auths.Authenticator):
    typeName = _('Internal Database')
    typeType = 'InternalDBAuth'
    typeDescription = _(
        'Internal dabasase authenticator. Doesn\'t use external sources'
    )
    iconFile = 'auth.png'

    # If we need to enter the password for this user
    needsPassword = True

    # This is the only internal source
    isExternalSource = False

    differentForEachHost = gui.CheckBoxField(
        label=_('Different user for each host'),
        order=1,
        tooltip=_('If checked, each host will have a different user name'),
        defvalue="false",
        rdonly=True,
        tab=gui.ADVANCED_TAB,
    )
    reverseDns = gui.CheckBoxField(
        label=_('Reverse DNS'),
        order=2,
        tooltip=_('If checked, the host will be reversed dns'),
        defvalue="false",
        rdonly=True,
        tab=gui.ADVANCED_TAB,
    )
    acceptProxy = gui.CheckBoxField(
        label=_('Accept proxy'),
        order=3,
        tooltip=_(
            'If checked, requests via proxy will get FORWARDED ip address (take care with this bein checked, can take internal IP addresses from internet)'
        ),
        tab=gui.ADVANCED_TAB,
    )

    def getIp(self) -> str:
        ip = (
            getRequest().ip_proxy if self.acceptProxy.isTrue() else getRequest().ip
        )  # pylint: disable=maybe-no-member
        if self.reverseDns.isTrue():
            try:
                return str(
                    dns.resolver.query(dns.reversename.from_address(ip).to_text(), 'PTR')[0]
                )
            except Exception:
                pass
        return ip

    def mfaIdentifier(self, username: str) -> str:
        try:
            return self.dbAuthenticator().users.get(name=username.lower(), state=State.ACTIVE).mfa_data
        except Exception:  # User not found
            return ''

    def transformUsername(self, username: str) -> str:
        username = username.lower()
        if self.differentForEachHost.isTrue():
            newUsername = self.getIp() + '-' + username
            # Duplicate basic user into username.
            auth = self.dbAuthenticator()
            # "Derived" users will belong to no group at all, because we will extract groups from "base" user
            # This way also, we protect from using forged "ip" + "username", because those will belong in fact to no group
            # and access will be denied
            try:
                usr = auth.users.get(name=username, state=State.ACTIVE)
                parent = usr.uuid
                usr.id = usr.uuid = None  # type: ignore  # Empty id
                if usr.real_name.strip() == '':
                    usr.real_name = usr.name
                usr.name = newUsername
                usr.parent = parent
                usr.save()
            except Exception:
                pass  # User already exists
            username = newUsername

        return username

    def authenticate(
        self, username: str, credentials: str, groupsManager: 'auths.GroupsManager'
    ) -> bool:
        username = username.lower()
        logger.debug('Username: %s', username)
        dbAuth = self.dbAuthenticator()
        try:
            user: 'models.User' = dbAuth.users.get(name=username, state=State.ACTIVE)
        except Exception:
            authLogLogin(getRequest(), self.dbAuthenticator(), username, 'Invalid user')
            return False

        if user.parent:  # Direct auth not allowed for "derived" users
            return False

        # Internal Db Auth has its own groups. (That is, no external source). If a group is active it is valid
        if cryptoManager().checkHash(credentials, user.password):
            groupsManager.validate([g.name for g in user.groups.all()])
            return True
        authLogLogin(getRequest(), self.dbAuthenticator(), username, 'Invalid password')
        return False

    def getGroups(self, username: str, groupsManager: 'auths.GroupsManager'):
        dbAuth = self.dbAuthenticator()
        try:
            user: 'models.User' = dbAuth.users.get(name=username.lower(), state=State.ACTIVE)
        except Exception:
            return

        groupsManager.validate([g.name for g in user.groups.all()])

    def getRealName(self, username: str) -> str:
        # Return the real name of the user, if it is set
        try:
            user = self.dbAuthenticator().users.get(name=username.lower(), state=State.ACTIVE)
            return user.real_name or username
        except Exception:
            return super().getRealName(username)

    def createUser(self, usrData):
        pass

    @staticmethod
    def test(env, data):
        return [True, _("Internal structures seems ok")]

    def check(self):
        return _("All seems fine in the authenticator.")

    def __str__(self):
        return "Internal DB Authenticator Authenticator"
