from __future__ import unicode_literals

from httplib2 import Http
import json

rest_url = 'http://172.27.0.1:8000/rest/'

headers = {}

# Hace login con el root, puede usarse cualquier autenticador y cualquier usuario, pero en la 1.5 solo está implementado poder hacer
# este tipo de login con el usuario "root"
def login():
    global headers
    h = Http()

    # parameters = '{ "auth": "admin", "username": "root", "password": "temporal" }'
    parameters = '{ "auth": "casa", "username": "172.27.0.1", "password": "" }'

    resp, content = h.request(rest_url + 'auth/login', method='POST', body=parameters)

    if resp['status'] != '200':  # Authentication error due to incorrect parameters, bad request, etc...
        print "Authentication error"
        return -1

    # resp contiene las cabeceras, content el contenido de la respuesta (que es json), pero aún está en formato texto
    res = json.loads(content)
    print res
    if res['result'] != 'ok':  # Authentication error
        print "Authentication error"
        return -1

    headers['X-Auth-Token'] = res['token']

    return 0

def logout():
    global headers
    h = Http()

    resp, content = h.request(rest_url + 'auth/logout', headers=headers)

    if resp['status'] != '200':  # Logout error due to incorrect parameters, bad request, etc...
        print "Error requesting logout"
        return -1

    # Return value of logout method is nonsense (returns always done right now, but it's not important)

    return 0

# Sample response from request_pools
# [
#     {
#        u'initial_srvs': 0,
#        u'name': u'WinAdolfo',
#        u'max_srvs': 0,
#        u'comments': u'',
#        u'id': 6,
#        u'state': u'A',
#        u'user_services_count': 3,
#        u'cache_l2_srvs': 0,
#        u'service_id': 9,
#        u'provider_id': 2,
#        u'cache_l1_srvs': 0,
#        u'restrained': False}
# ]

def request_services():
    h = Http()

    resp, content = h.request(rest_url + 'connection', headers=headers)
    if resp['status'] != '200':  # error due to incorrect parameters, bad request, etc...
        print "Error requesting services"
        print resp, content
        return {}

    return json.loads(content)

if __name__ == '__main__':
    if login() == 0:  # If we can log in, will get the pools correctly
        res = request_services()
        print res
        print logout()  # This will success
