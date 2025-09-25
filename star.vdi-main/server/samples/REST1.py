from __future__ import unicode_literals

from httplib2 import Http
import json
import sys

rest_url = 'http://172.27.0.1:8000/vdi/rest/'

headers = {}

# Hace login con el root, puede usarse cualquier autenticador y cualquier usuario, pero en la 1.5 solo está implementado poder hacer
# este tipo de login con el usuario "root"
def login():
    global headers
    h = Http()

    # parameters = '{ "auth": "admin", "username": "root", "password": "temporal" }'
    # parameters = '{ "auth": "interna", "username": "admin", "password": "temporal" }'
    parameters = '{ "auth": "interna", "username": "admin.1", "password": "temporal" }'

    resp, content = h.request(rest_url + 'auth/login', method='POST', body=parameters)

    if resp['status'] != '200':  # Authentication error due to incorrect parameters, bad request, etc...
        print("Authentication error")
        return -1

    # resp contiene las cabeceras, content el contenido de la respuesta (que es json), pero aún está en formato texto
    res = json.loads(content)
    print(res)
    if res['result'] != 'ok':  # Authentication error
        print("Authentication error")
        return -1

    headers['X-Auth-Token'] = res['token']

    return 0


def logout():
    global headers
    h = Http()

    resp, content = h.request(rest_url + 'auth/logout', headers=headers)

    if resp['status'] != '200':  # Logout error due to incorrect parameters, bad request, etc...
        print("Error requesting logout")
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

def request_pools():
    h = Http()

    resp, content = h.request(rest_url + 'servicespools/overview', headers=headers)
    if resp['status'] != '200':  # error due to incorrect parameters, bad request, etc...
        print("Error requesting pools")
        return {}

    return json.loads(content)

# PATH: /rest/providers/[provider_id]/services/[service_id]
def request_service_info(provider_id, service_id):
    h = Http()

    resp, content = h.request(rest_url + 'providers/{0}/services/{1}'.format(provider_id, service_id), headers=headers)
    if resp['status'] != '200':  # error due to incorrect parameters, bad request, etc...
        print("Error requesting pools: response: {}, content: {}".format(resp, content))
        return None

    return json.loads(content)

if __name__ == '__main__':
    # request_pools()  # Not logged in, this will generate an error

    if login() == 0:  # If we can log in, will get the pools correctly
        res = request_pools()
        print(res)
        sys.exit(0)
        for r in res:
            res2 = request_service_info(r['provider_id'], r['service_id'])
            if res2 is not None:
                print("Base Service info por pool {0}: {1}".format(r['name'], res2['type']))
            else:
                print("Base service {} is not accesible".format(r['name']))
        print("First logout")
        print(logout())  # This will success
        print("Second logout")
        print(logout())  # This will fail (already logged out)
        # Also new requests will fail
        print(request_pools())
        # Until we do log in again
        login()
        print(request_pools())

