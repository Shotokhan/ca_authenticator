import base64
import flask
import json
import os
from functools import wraps


def from_b64(msg):
    decoded = base64.b64decode(msg)
    return decoded


def to_b64(msg):
    try:
        encoded = base64.b64encode(msg.encode())
    except AttributeError:
        encoded = base64.b64encode(msg)
    return encoded.decode()


def json_response(msg_dict, status_code):
    res = flask.Response(json.dumps(msg_dict, default=str), status=status_code, mimetype='application/json')
    return res


def get_nonce(key_size, modulus, nonces):
    while True:
        # https://cryptography.io/en/latest/random-numbers/?highlight=random
        nonce = int.from_bytes(os.urandom(key_size // 8), byteorder='big')
        if nonce < modulus and nonce not in nonces:
            break
    return nonce


def filter_validity_days(validity):
    validity = int(validity)
    validity = max(validity, 1)
    validity = min(validity, 28)
    return validity


def get_oidc_info(oidc):
    info = oidc.user_getinfo(['preferred_username', 'realm_access', 'resource_access'])
    username = info.get('preferred_username')
    role = info.get('realm_access').get('roles')[0]
    resources = info.get('resource_access').get('flask-app').get('roles')
    return username, role, resources


def catch_error(func):
    @wraps(func)
    def exceptionLogger(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print("Exception in {}: {} {}".format(func.__name__, e.__class__.__name__, str(e)))
            # TODO: remove this debug feature
            debug = True
            if debug:
                return json_response({"msg": f"Generic error {func.__name__} {e.__class__.__name__} {str(e)}"}, 500)
            else:
                return json_response({"msg": "Generic error"}, 500)

    return exceptionLogger
