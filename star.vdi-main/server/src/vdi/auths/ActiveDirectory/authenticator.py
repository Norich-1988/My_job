import logging, typing, ldap
from django.utils.translation import gettext_noop as _
from vdi.core import auths
from vdi.core.managers import cryptoManager
from vdi.core.ui import gui
from vdi.core.util import ldaputil
if typing.TYPE_CHECKING:
    from vdi import models
    from vdi.core.environment import Environment
logger = logging.getLogger(__name__)
LDAP_RESULT_LIMIT = 100

class ActiveDirectoryAuthenticator(auths.Authenticator):
    host = gui.TextField(length=64, label=(_('Host')), order=1, tooltip=(_('Active Directory Server IP or Hostname')), required=True)
    ssl = gui.CheckBoxField(label=(_('Use SSL')), order=2, tooltip=(_('If checked, a ssl connection to Active Directory will be used')))
    compat = gui.ChoiceField(label=(_('Compatibility')), order=3, tooltip=(_('Compatibility of AD connection (Usually windows 2000 and later)')), values=[
     {'id':'nt', 
      'text':'Windows NT'}, {'id':'w2x',  'text':'Windows 2000 and later'}],
      required=True,
      defvalue='w2x',
      rdonly=True)
    username = gui.TextField(length=64, label=(_('User')), order=4, tooltip=(_('Username with read privileges on the base selected (use USER@DOMAIN.DOM form for this)')), required=True, tab=(gui.CREDENTIALS_TAB))
    password = gui.PasswordField(length=32, label=(_('Password')), order=5, tooltip=(_('Password of the ldap user')), required=True, tab=(gui.CREDENTIALS_TAB))
    timeout = gui.NumericField(length=3, label=(_('Timeout')), defvalue='10', order=6, tooltip=(_('Timeout in seconds of connection to Active Directory')), required=True)
    searchBase = gui.TextField(length=128, label=(_('Override Base')), order=4, tooltip=(_('If not empty, will override AD search base with this value (format: dc=..., dc=...)')), required=False, defvalue='', tab=(gui.ADVANCED_TAB))
    typeName = _('Active Directory Authenticator')
    typeType = 'ActiveDirectoryAuthenticator'
    typeDescription = _('Authenticate against Active Directory')
    iconFile = 'auth.png'
    isExternalSource = True
    needsPassword = False
    userNameLabel = _('Username')
    groupNameLabel = _('Group')
    passwordLabel = _('Password')
    _connection: typing.Any = None
    _host: str = ''
    _ssl: bool = True
    _username: str = ''
    _password: str = ''
    _timeout: str = ''
    _compat: str = ''
    _searchBase: str = ''

    def initialize(self, values: typing.Optional[typing.Dict[(str, typing.Any)]]) -> None:
        if values:
            self._host = values['host']
            self._ssl = gui.strToBool(values['ssl'])
            self._username = values['username']
            self._password = values['password']
            self._timeout = values['timeout']
            self._compat = values['compat']
            self._searchBase = values['searchBase'].strip()
            if self._username.find('@') == -1:
                raise auths.Authenticator.ValidationException(_('Must specify the username in the form USERNAME@DOMAIN.DOM'))

    def valuesDict(self):
        return {'host':self._host,  'ssl':gui.boolToStr(self._ssl), 
         'username':self._username, 
         'password':self._password, 
         'timeout':self._timeout, 
         'compat':self._compat, 
         'searchBase':self._searchBase}

    def marshal(self) -> bytes:
        return '\t'.join([
         'v4',
         self._host,
         gui.boolToStr(self._ssl),
         self._username,
         cryptoManager().encrypt(self._password),
         self._timeout,
         self._compat,
         self._searchBase]).encode('utf8')

    def unmarshal(self, data: bytes) -> None:
        vals = data.decode('utf8').split('\t')
        logger.debug('Data: %s', vals[1:])
        if vals[0] == 'v1':
            self._host, ssl, self._username, self._password, self._timeout = vals[1:]
            self._compat = 'nt'
            self._ssl = gui.strToBool(ssl)
        else:
            if vals[0] in ('v2', 'v3', 'v4'):
                self._host, ssl, self._username, self._password, self._timeout, self._compat = vals[1:7]
                self._ssl = gui.strToBool(ssl)
                self._searchBase = ''
                if vals[0] in ('v3', 'v4'):
                    self._searchBase = vals[7]
                    if vals[0] == 'v4':
                        self._password = cryptoManager().decrypt(self._password)

    def __getUserField(self) -> str:
        if self._compat == 'nt':
            return 'sAMAccountName'
        return 'userPrincipalName'

    def __getGroupField(self):
        if self._compat == 'nt':
            return 'sAMAccountName'
        return 'cn'

    def __composeUsername(self, username: str) -> str:
        if self._compat == 'w2x':
            if username.find('@') == -1:
                username = username + '@' + self._username.split('@')[1]
        return username

    def __getLdapBase(self) -> str:
        val = self._searchBase.strip()
        if not val:
            val = ','.join(['DC=' + v for v in self._username.split('@')[1].split('.')])
        return val

    def __connection(self) -> typing.Any:
        if not self._connection:
            self._connection = ldaputil.connection((self._username),
              (self._password), (self._host), ssl=(self._ssl),
              timeout=(int(self._timeout)),
              debug=False)
        return self._connection

    def __connectAs(self, username: str, password: str) -> typing.Any:
        return ldaputil.connection(username, password, (self._host), ssl=(self._ssl), timeout=(int(self._timeout)), debug=False)

    def __getUser(self, username: str) -> typing.Optional[ldaputil.LDAPResultType]:
        return ldaputil.getFirst(con=(self._ActiveDirectoryAuthenticator__connection()),
          base=(self._ActiveDirectoryAuthenticator__getLdapBase()),
          objectClass='user',
          field=(self._ActiveDirectoryAuthenticator__getUserField()),
          value=(self._ActiveDirectoryAuthenticator__composeUsername(username)),
          attributes=[
         'displayName', 'memberOf', 'primaryGroupID'],
          sizeLimit=LDAP_RESULT_LIMIT)

    def __getGroup(self, groupName: str) -> typing.Optional[ldaputil.LDAPResultType]:
        return ldaputil.getFirst(con=(self._ActiveDirectoryAuthenticator__connection()),
          base=(self._ActiveDirectoryAuthenticator__getLdapBase()),
          objectClass='group',
          field=(self._ActiveDirectoryAuthenticator__getGroupField()),
          value=groupName,
          attributes=[
         'memberOf', 'description'],
          sizeLimit=LDAP_RESULT_LIMIT)

    def __followGroups(self, memberOfList: typing.List[str], alreadyAddedSet: typing.Optional[typing.Set[str]]=None) -> typing.List[str]:
        _filter = ''
        memberSet = set(memberOfList)
        if alreadyAddedSet:
            memberSet = memberSet.difference(alreadyAddedSet)
        for m in memberSet:
            if m == '':
                continue
            mEscaped = ldaputil.escape(m)
            if _filter == '':
                _filter = '(distinguishedName=' + mEscaped + ')'
            else:
                _filter = '(|(distinguishedName=' + mEscaped + ')' + _filter + ')'

        if not _filter:
            return list()
        else:
            if alreadyAddedSet is not None:
                memberSet = memberSet.union(alreadyAddedSet)
            logger.debug('Follow group filter: %s', _filter)
            grps = set()
            groupFieldName = self._ActiveDirectoryAuthenticator__getGroupField()
            for adGroup in ldaputil.getAsDict(con=(self._ActiveDirectoryAuthenticator__connection()),
              base=(self._ActiveDirectoryAuthenticator__getLdapBase()),
              ldapFilter=_filter,
              attrList=[
             groupFieldName, 'memberOf', 'description'],
              sizeLimit=(10 * LDAP_RESULT_LIMIT)):
                if groupFieldName in adGroup:
                    for k in adGroup[groupFieldName]:
                        grps.add(k)

                if not 'memberOf' not in adGroup:
                    if not adGroup['memberOf']:
                        continue
                        grps = grps.union(set(self._ActiveDirectoryAuthenticator__followGroups(adGroup['memberOf'], memberSet)))

            logger.debug('Groups: %s', grps)
            return list(grps)

    def __getGroupsName(self, user: ldaputil.LDAPResultType):
        groups = []
        if user:
            groups = self._ActiveDirectoryAuthenticator__followGroups(user['memberOf'])
        return groups

    def __getUserRealName(self, adUser: ldaputil.LDAPResultType) -> str:
        try:
            displayName = adUser.get('displayName', [''])[0]
        except Exception:
            displayName = ''

        logger.debug('getUserRealName res: %s', displayName)
        return displayName

    def authenticate(self, username: str, credentials: str, groupsManager: 'auths.GroupsManager') -> bool:
        try:
            if not credentials:
                raise Exception('Credentials not provided')
            adUser = self._ActiveDirectoryAuthenticator__getUser(username)
            if adUser is None:
                return False
            self._ActiveDirectoryAuthenticator__connectAs(adUser['dn'], credentials)
            groupsManager.validate(self._ActiveDirectoryAuthenticator__getGroupsName(adUser))
            return True
        except Exception:
            logger.exception('At authenticate')
            return False

    def createUser(self, usrData: typing.Dict[(str, str)]) -> None:
        usrData['name'] = self._ActiveDirectoryAuthenticator__composeUsername(usrData['name'])
        adUser = self._ActiveDirectoryAuthenticator__getUser(usrData['name'])
        if not adUser:
            raise auths.exceptions.AuthenticatorException(_('Username not found'))
        usrData['real_name'] = self._ActiveDirectoryAuthenticator__getUserRealName(adUser)

    def getRealName(self, username: str) -> str:
        adUser = self._ActiveDirectoryAuthenticator__getUser(username)
        if adUser is None:
            return username
        return self._ActiveDirectoryAuthenticator__getUserRealName(adUser)

    def modifyUser(self, usrData: typing.Dict[(str, str)]) -> None:
        return self.createUser(usrData)

    def createGroup(self, groupData: typing.Dict[(str, str)]) -> None:
        res = self._ActiveDirectoryAuthenticator__getGroup(groupData['name'])
        if res is None:
            raise auths.exceptions.AuthenticatorException(_('Group not found'))
        if groupData.get('comments', '') == '':
            groupData['comments'] = res.get('description', [''])[0].replace('\r', ' ').replace('\n', ' ')

    def modifyGroup(self, groupData: typing.Dict[(str, str)]) -> None:
        return self.createGroup(groupData)

    def getGroups(self, username: str, groupsManager: 'auths.GroupsManager'):
        adUser = self._ActiveDirectoryAuthenticator__getUser(username)
        if adUser is None:
            raise auths.exceptions.AuthenticatorException(_('Username not found'))
        groupsManager.validate(self._ActiveDirectoryAuthenticator__getGroupsName(adUser))

    def searchUsers(self, pattern: str) -> typing.Iterable[typing.Dict[(str, str)]]:
        try:
            userFieldName = self._ActiveDirectoryAuthenticator__getUserField()
            res = []
            for r in ldaputil.getAsDict(con=(self._ActiveDirectoryAuthenticator__connection()),
              base=(self._ActiveDirectoryAuthenticator__getLdapBase()),
              ldapFilter=('(&(&(objectClass=user)({}={}*))(objectCategory=person))'.format(userFieldName, ldaputil.escape(pattern))),
              attrList=[
             userFieldName, 'displayName', 'memberOf', 'primaryGroupID'],
              sizeLimit=LDAP_RESULT_LIMIT):
                res.append({'id':r[userFieldName][0].split('@')[0], 
                 'name':self._ActiveDirectoryAuthenticator__getUserRealName(r)})

            return res
        except Exception:
            logger.exception('Exception: ')
            raise auths.exceptions.AuthenticatorException(_('Too many results, be more specific'))

    def searchGroups(self, pattern: str) -> typing.Iterable[typing.Dict[(str, str)]]:
        logger.debug('Searching groups "%s"', pattern)
        try:
            groupFieldName = self._ActiveDirectoryAuthenticator__getGroupField()
            res = []
            for r in ldaputil.getAsDict(con=(self._ActiveDirectoryAuthenticator__connection()),
              base=(self._ActiveDirectoryAuthenticator__getLdapBase()),
              ldapFilter=('(&(objectClass=group)({}={}*))'.format(groupFieldName, ldaputil.escape(pattern))),
              attrList=[
             groupFieldName, 'memberOf', 'description'],
              sizeLimit=LDAP_RESULT_LIMIT):
                res.append({'id':r[groupFieldName][0], 
                 'name':r['description'][0]})

            return res
        except Exception:
            logger.exception('Exception: ')
            raise auths.exceptions.AuthenticatorException(_('Too many results, be more specific'))
    
    def transformUsername(self, username: str) -> str:
        return self._ActiveDirectoryAuthenticator__composeUsername(username)

    @staticmethod
    def test(env, data):
        try:
            auth = ActiveDirectoryAuthenticator(None, env, data)
            return auth.testConnection()
        except Exception as e:
            try:
                logger.error('Exception found testing Active Directory auth %s: %s', e.__class__, e)
                return [False, 'Error testing connection']
            finally:
                e = None
                del e

    def testConnection(self):
        if self._username.find('@') == -1:
            return [
             False, _('Must specify the username in the form USERNAME@DOMAIN.DOM')]
        try:
            con = self._ActiveDirectoryAuthenticator__connection()
        except Exception as e:
            try:
                return [
                 False, str(e)]
            finally:
                e = None
                del e

        try:
            logger.debug('Testing connection')
            con.search_s(base=(self._ActiveDirectoryAuthenticator__getLdapBase()), scope=(ldap.SCOPE_BASE))
        except Exception:
            return [
             False, _('Domain seems to be incorrect, please check it')]
        else:
            try:
                logger.debug('Testing user existence')
                if len(con.search_ext_s(base=(self._ActiveDirectoryAuthenticator__getLdapBase()), scope=(ldap.SCOPE_SUBTREE), filterstr='(objectClass=user)', sizelimit=1)) == 1:
                    raise Exception()
                return [
                 False, _('Server does not seem an Active Directory (it does not have user objects)')]
            except Exception:
                pass

            try:
                if len(con.search_ext_s(base=(self._ActiveDirectoryAuthenticator__getLdapBase()), scope=(ldap.SCOPE_SUBTREE), filterstr='(objectClass=group)', sizelimit=1)) == 1:
                    raise Exception()
                return [
                 False, _('Server does not seem an Active Directory (it does not have group objects)')]
            except Exception:
                pass

            return [
             True, _('Connection params seem correct, test was succesfully executed')]

    def __str__(self):
        return 'Active Directory Auth: {0}:{1}@{2} timeout: {3}, ssl: {4}'.format(self._username, self._password, self._host, self._timeout, self._ssl)
