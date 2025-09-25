import logging
import typing

from django.utils.translation import gettext_noop as _

from vdi.core.ui import gui
from vdi.core import auths
from vdi.core.managers import cryptoManager
from vdi.core.auths.auth import authLogLogin
from vdi.core.util.request import getRequest

from . import client

if typing.TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class RadiusAuth(auths.Authenticator):
    """
    VDI Radius authenticator
    """

    typeName = _('Radius Authenticator')
    typeType = 'RadiusAuthenticator'
    typeDescription = _('Radius Authenticator')
    iconFile = 'radius.png'

    userNameLabel = _('User')
    groupNameLabel = _('Group')

    server = gui.TextField(
        length=64,
        label=_('Host'),
        order=1,
        tooltip=_('Radius Server IP or Hostname'),
        required=True,
    )
    port = gui.NumericField(
        length=5,
        label=_('Port'),
        defvalue='1812',
        order=2,
        tooltip=_('Radius authentication port (usually 1812)'),
        required=True,
    )
    secret = gui.TextField(
        length=64,
        label=_('Secret'),
        order=3,
        tooltip=_('Radius client secret'),
        required=True,
    )

    nasIdentifier = gui.TextField(
        length=64,
        label=_('NAS Identifier'),
        defvalue='vdi-server',
        order=10,
        tooltip=_('NAS Identifier for Radius Server'),
        required=True,
        tab=gui.ADVANCED_TAB,
    )

    appClassPrefix = gui.TextField(
        length=64,
        label=_('App Prefix for Class Attributes'),
        defvalue='',
        order=11,
        tooltip=_('Application prefix for filtering groups from "Class" attribute'),
        tab=gui.ADVANCED_TAB,
    )

    globalGroup = gui.TextField(
        length=64,
        label=_('Global group'),
        defvalue='',
        order=12,
        tooltip=_('If set, this value will be added as group for all radius users'),
        tab=gui.ADVANCED_TAB,
    )
    mfaAttr = gui.TextField(
        length=2048,
        multiline=2,
        label=_('MFA attribute'),
        order=13,
        tooltip=_('Attribute from where to extract the MFA code'),
        required=False,
        tab=gui.MFA_TAB,
    )

    def initialize(self, values: typing.Optional[typing.Dict[str, typing.Any]]) -> None:
        pass

    def radiusClient(self) -> client.RadiusClient: 
        """ Return a new radius client . """
        return client.RadiusClient(
            self.server.value,
            self.secret.value.encode(),
            authPort=self.port.num(),
            nasIdentifier=self.nasIdentifier.value,
            appClassPrefix=self.appClassPrefix.value,
        )

    def mfaStorageKey(self, username: str) -> str:
        return 'mfa_' + str(self.dbAuthenticator().uuid) + username

    def mfaIdentifier(self, username: str) -> str:
        return self.storage.getPickle(self.mfaStorageKey(username)) or ''

    def authenticate(
        self, username: str, credentials: str, groupsManager: 'auths.GroupsManager'
    ) -> bool:
        try:
            connection = self.radiusClient()
            groups, mfaCode = connection.authenticate(username=username, password=credentials, mfaField=self.mfaAttr.value.strip())
            # store the user mfa attribute if it is set
            if mfaCode:
                self.storage.putPickle(
                    self.mfaStorageKey(username),
                    mfaCode,
                )

        except Exception:
            authLogLogin(getRequest(), self.dbAuthenticator(), username, 'Access denied by Raivdi')
            return False

        if self.globalGroup.value.strip():
            groups.append(self.globalGroup.value.strip())

        # Cache groups for "getGroups", because radius will not send us those
        with self.storage.map() as storage:
            storage[username] = groups

        # Validate groups
        groupsManager.validate(groups)

        return True

    def getGroups(self, username: str, groupsManager: 'auths.GroupsManager') -> None:
        with self.storage.map() as storage:
            groupsManager.validate(storage.get(username, []))

    def createUser(self, usrData: typing.Dict[str, str]) -> None:
        pass

    def removeUser(self, username: str) -> None:
        with self.storage.map() as storage:
            if username in storage:
                del storage[username]
        return super().removeUser(username)

    @staticmethod
    def test(env, data): 
        """ Test the connection to the server . """
        try:
            auth = RadiusAuth(None, env, data)  # type: ignore
            return auth.testConnection()
        except Exception as e:
            logger.error(
                "Exception found testing Radius auth %s: %s", e.__class__, e
            )
            return [False, _('Error testing connection')]

    def testConnection(self): 
        """ Test connection to Radius Server """
        try:
            connection = self.radiusClient()
            # Reply is not important...
            connection.authenticate(cryptoManager().randomString(10), cryptoManager().randomString(10), mfaField=self.mfaAttr.value.strip())
        except client.RadiusAuthenticationError as e:
            pass
        except Exception:
            logger.exception('Connecting')
            return [False, _('Connection to Radius server failed')]
        return [True, _('Connection to Radius server seems ok')]
