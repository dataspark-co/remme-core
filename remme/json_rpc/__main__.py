import logging
import json
from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple

from jsonrpc import JSONRPCResponseManager, dispatcher
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from remme.token.token_client import PermissionClient, TokenClient
from remme.token.token_handler import PermissionHandler
from remme.shared.exceptions import KeyNotFound


perm_client = PermissionClient()
token_client = TokenClient()


log = logging.getLogger('werkzeug')
log.setLevel(logging.DEBUG)


class Storage:

    mem = {}
    handler = PermissionHandler

    @classmethod
    def set_state(cls, kdict):
        cls.mem.update(kdict)

    @classmethod
    def get_value(cls, key):
        try:
            return cls.mem[key]
        except KeyError:
            raise KeyNotFound("404")

    @classmethod
    def get_state(cls, args):
        class Mock:
            pass

        mock = Mock()
        try:
            state = cls.get_value(args[0])
            mock.data = state
            return [mock]
        except KeyNotFound:
            pass


storage = Storage()


@dispatcher.add_method
def create_certificate():
    encryption_algorithm = serialization.NoEncryption()
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    key_export = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm,
    )
    return json.dumps({
        'private_container_key': key_export.decode('utf-8'),
    })


@dispatcher.add_method
def get_document(pub_container_key, document_id):
    data = perm_client.get_document(document_id, storage=storage)
    return json.dumps({
        'id': data.id,
        'data': data.data,
    })


@dispatcher.add_method
def create_document(pub_container_key, document_id, data, access_key):
    data = perm_client.create_document(pub_container_key, document_id, data, access_key, storage=storage)
    return json.dumps({
        'id': data.document_id,
    })


@dispatcher.add_method
def update_document(pub_container_key, document_id, data, access_list):
    data = perm_client.update_document(pub_container_key, document_id, data, access_list, storage=storage)
    return json.dumps({
        'id': data.document_id,
    })


@dispatcher.add_method
def create_access(pub_container_key, document_id, grant_pub_container_key):
    data = perm_client.create_access(pub_container_key, document_id, grant_pub_container_key, storage=storage)
    return json.dumps({
        'status': 'ok',
    })


@dispatcher.add_method
def get_access_list(pub_container_key, document_id):
    data = perm_client.get_access_list(document_id, storage=storage)
    return json.dumps({
        'accesses': [{'pub_container_key': el.pub_container_key, 'access_key': el.access_key} for el in data],
    })


@Request.application
def application(request):
    response = JSONRPCResponseManager.handle(
        request.data, dispatcher)
    return Response(response.json, mimetype='application/json')


if __name__ == '__main__':
    print("Starting HTTP server ...")
    print("URL: http://0.0.0.0:8099")
    run_simple('0.0.0.0', 8099, application)
