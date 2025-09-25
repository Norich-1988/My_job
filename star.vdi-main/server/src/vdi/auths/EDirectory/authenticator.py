import re, logging, typing, ldap
from django.utils.translation import gettext_noop as _
from vdi.core.ui import gui
from vdi.core import auths
from vdi.core.util import ldaputil
logger = logging.getLogger(__name__)
LDAP_RESULT_LIMIT = 50
EDIR_TIMEOUT = 5
EDIR_BASE_REGEX = '.*,(.*)$'
EDIR_USERCLASS = 'Person'
EDIR_ATTR_ID = 'cn'
EDIR_FULLNAME = 'fullName'
EDIR_GROUP_NAME = 'groupMembership'
EDIR_GROUPS_REGEX = 'cn=([^,]*)'

class EDirectory(auths.Authenticator):
    host = gui.TextField(length=64, label=(_('Host')), order=1, tooltip=(_('EDirectory Server IP or Hostname')), required=True)
    port = gui.NumericField(length=5, label=(_('Port')), defvalue='389', order=2, tooltip=(_('Ldap port (usually 389 for non ssl and 636 for ssl)')), required=True)
    ssl = gui.CheckBoxField(label=(_('Use SSL')), order=3, tooltip=(_('If checked, the connection will be ssl, using port 636 instead of 389')))
    username = gui.TextField(length=64, label=(_('User')), order=4, tooltip=(_('Username with read privileges on the eDirectory')), required=True, tab=(gui.CREDENTIALS_TAB))
    password = gui.PasswordField(length=32, label=(_('Password')), order=5, tooltip=(_('Password of the ldap user')), required=True, tab=(gui.CREDENTIALS_TAB))
    timeout = gui.NumericField(length=3, label=(_('Timeout')), defvalue='10', order=6, tooltip=(_('Timeout in seconds of connection to LDAP')), required=True, minValue=1)
    typeName = _('eDirectory Authenticator')
    typeType = 'EDirectoryAuthenticator'
    typeDescription = _('Authenticate against eDirectory')
    iconFile = 'eDirectory.png'
    isExternalSource = True
    needsPassword = False
    userNameLabel = _('Username')
    groupNameLabel = _('Group')
    _connection = None
    _connection: typing.Optional[typing.Any]

    def initialize(self, values: typing.Optional[typing.Dict[(str, typing.Any)]]) -> None:
        if values:
            if self.username.value.find(',') == -1:
                raise auths.Authenticator.ValidationException('Must specify the admin username in the form cn=...,o=...')

    def __connection(self) -> typing.Any:
        if not self._connection:
            self._connection = ldaputil.connection((self.username.value),
              (self.password.value),
              (self.host.value),
              port=(self.port.num()),
              ssl=(self.ssl.isTrue()),
              timeout=EDIR_TIMEOUT,
              debug=False)
        return self._connection

    def __connectAs(self, username: str, password: str) -> typing.Any:
        return ldaputil.connection(username, password, (self.host.value), port=(self.port.num()), ssl=(self.ssl.isTrue()), timeout=EDIR_TIMEOUT, debug=False)

    def __getLdapBase(self) -> str:
        ma = re.search(EDIR_BASE_REGEX, self.username.value)
        if not ma:
            logger.error('Username %s for edirectory is in invalid format', self.username.value)
            return ''
        return ma.group(1)

    def __getUser(self, username: str) -> typing.Optional[ldaputil.LDAPResultType]:
        if username.find(' ') != -1:
            logger.debug('Username for eDirectory contains spaces, failing')
            return
        return ldaputil.getFirst(con=(self._EDirectory__connection()),
          base=(self._EDirectory__getLdapBase()),
          objectClass=EDIR_USERCLASS,
          field=EDIR_ATTR_ID,
          value=username,
          attributes=[
         EDIR_FULLNAME, EDIR_ATTR_ID, EDIR_GROUP_NAME],
          sizeLimit=LDAP_RESULT_LIMIT)

    def __getGroups(self, user: ldaputil.LDAPResultType) -> typing.List[str]:
        foundGroups = user[EDIR_GROUP_NAME]
        if not isinstance(foundGroups, (list, tuple)):
            foundGroups = [
             foundGroups]
        logger.debug('Groups: %s', foundGroups)
        logger.debug('Re: %s', EDIR_GROUPS_REGEX)
        reGroup = re.compile(EDIR_GROUPS_REGEX)
        res = []
        for group in foundGroups:
            ma = reGroup.match(group)
            if ma is not None:
                for m in ma.groups():
                    res.append(m)

        logger.debug('Res: %s', res)
        return res

    def __getUserRealName(self, user: ldaputil.LDAPResultType) -> str:
        fullNameList = user.get(EDIR_FULLNAME, [''])
        return ' '.join([' '.join([str(k) for k in fullNameList]) if isinstance(fullNameList, (list, tuple)) else fullNameList]).strip()

    def authenticate(self, username: str, credentials: str, groupsManager: 'auths.GroupsManager') -> bool:
        try:
            user = self._EDirectory__getUser(username)
            if user is None:
                return False
            self._EDirectory__connectAs(user['dn'], credentials)
            groupsManager.validate(self._EDirectory__getGroups(user))
            return True
        except Exception:
            return False

    def createUser(self, usrData: typing.Dict[(str, str)]) -> None:
        res = self._EDirectory__getUser(usrData['name'])
        if res is None:
            raise auths.exceptions.AuthenticatorException(_('Username not found'))
        usrData['real_name'] = self._EDirectory__getUserRealName(res) or usrData['name']

    def getRealName(self, username: str) -> str:
        res = self._EDirectory__getUser(username)
        if not res:
            return username
        return self._EDirectory__getUserRealName(res) or username

    def modifyUser(self, usrData: typing.Dict[(str, str)]) -> None:
        return self.createUser(usrData)

    def getGroups(self, username: str, groupsManager: 'auths.GroupsManager'):
        user = self._EDirectory__getUser(username)
        if user is None:
            raise auths.exceptions.AuthenticatorException(_('Username not found'))
        groupsManager.validate(self._EDirectory__getGroups(user))

    def searchUsers(self, pattern: str) -> typing.Iterable[typing.Dict[(str, str)]]:
        try:
            res = []
            for r in ldaputil.getAsDict(con=(self._EDirectory__connection()), base=(self._EDirectory__getLdapBase()),
              ldapFilter=('(&(objectClass={})({}={}*))'.format(EDIR_USERCLASS, EDIR_ATTR_ID, ldaputil.escape(pattern))),
              attrList=[
             EDIR_FULLNAME, EDIR_ATTR_ID, EDIR_GROUP_NAME],
              sizeLimit=LDAP_RESULT_LIMIT):
                res.append({'id':r[EDIR_ATTR_ID][0], 
                 'name':self._EDirectory__getUserRealName(r)})

            return res
        except Exception:
            logger.exception('Exception: ')
            raise auths.exceptions.AuthenticatorException(_('Too many results, be more specific'))

    @staticmethod
    def test(env, data):
        try:
            auth = EDirectory(None, env, data)
            return auth.testConnection()
        except Exception as e:
            try:
                logger.error('Exception found testing Simple LDAP auth %s: %s', e.__class__, e)
                return [False, 'Error testing connection']
            finally:
                e = None
                del e

    def testConnection(self):
        try:
            con = self._EDirectory__connection()
        except Exception as e:
            try:
                return [
                 False, _('Edirectory connection error: {}'.format(e))]
            finally:
                e = None
                del e

        try:
            con.search_s(base=(self._EDirectory__getLdapBase()), scope=(ldap.SCOPE_BASE))
        except Exception:
            return [
             False, _('Ldap search base is incorrect')]
        else:
            try:
                if len(con.search_ext_s(base=(self._EDirectory__getLdapBase()), scope=(ldap.SCOPE_SUBTREE), filterstr=('(objectClass=%s)' % EDIR_USERCLASS), sizelimit=1)) == 1:
                    raise Exception()
                return [
                 False, _('Ldap user class seems to be incorrect (no user found by that class)')]
            except Exception:
                pass

            try:
                if len(con.search_ext_s(base=(self._EDirectory__getLdapBase()), scope=(ldap.SCOPE_SUBTREE), filterstr=('(%s=*)' % EDIR_ATTR_ID), sizelimit=1)) == 1:
                    raise Exception()
                return [
                 False, _('Ldap user id attribute seems to be incorrect (no user found by that attribute)')]
            except Exception:
                pass

            try:
                if len(con.search_ext_s(base=(self._EDirectory__getLdapBase()), scope=(ldap.SCOPE_SUBTREE), filterstr=('(%s=*)' % EDIR_GROUP_NAME), sizelimit=1)) == 1:
                    raise Exception()
                return [
                 False, _('Expected group attribute ' + EDIR_GROUP_NAME + ' not found. Ldap do not seems an eDiretory.')]
            except Exception:
                pass

            try:
                if len(con.search_ext_s(base=(self._EDirectory__getLdapBase()), scope=(ldap.SCOPE_SUBTREE), filterstr=('(&(objectClass=%s)(%s=*))' % (EDIR_USERCLASS, EDIR_ATTR_ID)), sizelimit=1)) == 1:
                    raise Exception()
                return [
                 False, _('Ldap user class or user id attr is probably wrong (Ldap is an eDirectory?)')]
            except Exception:
                pass

            return [
             True, _('Connection params seem correct, test was succesfully executed')]

    def __str__(self):
        return 'eDirectory Auth: {0}:{1}@{2}:{3},'.format(self.username.value, self.password.value, self.host.value, self.port.value)
