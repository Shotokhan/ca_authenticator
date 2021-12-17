import base64
import flask
import json
import os
import mongo_utils
from functools import wraps
import hashlib


def from_b64(msg):
    decoded = base64.b64decode(msg)
    return decoded


def to_b64(msg):
    try:
        encoded = base64.b64encode(msg.encode())
    except AttributeError:
        encoded = base64.b64encode(msg)
    return encoded.decode()


def json_response(msg_dict, status_code, headers=None):
    if headers is None:
        res = flask.Response(json.dumps(msg_dict, default=str), status=status_code, mimetype='application/json')
    else:
        res = flask.Response(json.dumps(msg_dict, default=str), status=status_code, mimetype='application/json', headers=headers)
    return res


def get_nonce(key_size, modulus, nonces):
    while True:
        # https://cryptography.io/en/latest/random-numbers/?highlight=random
        nonce = os.urandom(key_size // 8)
        hash_nonce = hashlib.sha1(nonce).hexdigest()
        nonce = int.from_bytes(nonce, byteorder='big')
        if nonce < modulus and hash_nonce not in nonces:
            break
    return nonce


def content_security_policy():
    nonce = to_b64(os.urandom(16))
    csp = """
    default-src 'none'; script-src 'nonce-{}' 'strict-dynamic' http: https: 'unsafe-inline'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'self'
    """.format(nonce)
    return csp, nonce


def filter_validity_days(validity, max_validity):
    validity = int(validity)
    validity = max(validity, 1)
    validity = min(validity, max_validity)
    return validity


def get_oidc_info(oidc):
    info = oidc.user_getinfo(['preferred_username', 'realm_access', 'resource_access'])
    username = info.get('preferred_username')
    role = info.get('realm_access').get('roles')[0]
    resources = info.get('resource_access').get('flask-app').get('roles')
    return username, role, resources


def subject_data_from_json(subject_data):
    try:
        subject_data = json.loads(subject_data)
    except json.JSONDecodeError:
        subject_data = json.loads(subject_data.decode().replace('\\', ''))
    return subject_data


def access_control(session, mongo_client, config, resource):
    subject_data = from_b64(session['subject'])
    subject_data = subject_data_from_json(subject_data)
    role = subject_data['role']
    role = {'role': role}
    resources = mongo_utils.get_resources_from_role(mongo_client, config['mongo']['db_name'], config['mongo']['collection_name'], role)
    return resource in resources


def disable_ssl_verification_oauth2_client(python_lib_path="/usr/local/lib/python3.9/site-packages"):
    transport = python_lib_path + "/oauth2client/transport.py"
    with open(transport, 'r') as f:
        code = f.read()
    old_line = "return httplib2.Http(*args, **kwargs)"
    new_line = "return httplib2.Http(*args, **kwargs, disable_ssl_certificate_validation=True)"
    code = code.replace(old_line, new_line)
    with open(transport, 'w') as f:
        f.write(code)
    flask_oidc_init = python_lib_path + "/flask_oidc/__init__.py"
    with open(flask_oidc_init, 'r') as f:
        code = f.read()
    old_line = "credentials.refresh(httplib2.Http())"
    new_line = "credentials.refresh(httplib2.Http(disable_ssl_certificate_validation=True))"
    code = code.replace(old_line, new_line)
    with open(flask_oidc_init, 'w') as f:
        f.write(code)


def catch_error(func):
    @wraps(func)
    def exceptionLogger(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print("Exception in {}: {} {}".format(func.__name__, e.__class__.__name__, str(e)))
            return json_response({"msg": "Generic error"}, 500)
    return exceptionLogger
