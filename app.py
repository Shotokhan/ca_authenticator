from flask import Flask, Response, request, session
from certificates_library import getSSLContext, loadCertificate, readCertificate, verifyCertificate, serializeCert, verifySignature
import sys
import project_utils
import uuid
import json
from datetime import timedelta


app = Flask(__name__, static_folder="/usr/src/app/volume/")
app.config['SECRET_KEY'] = uuid.uuid4().hex
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
ca_cert = None
global nonces
nonces = set()
nonce_list_lim = 40000


@app.route('/authenticate', methods=['POST'], strict_slashes=False)
@project_utils.catch_error
def authenticate():
    # {"cert": base64(cert)}
    global nonces
    cert = request.get_json(force=True)
    cert = project_utils.from_b64(cert['cert'])
    cert = loadCertificate(cert)
    valid = verifyCertificate(ca_cert, cert)
    if not valid:
        return project_utils.json_response({"msg": "Certificate validation failed"}, 400)
    else:
        pk = cert.public_key()
        challenge = project_utils.get_nonce(pk.key_size, pk.public_numbers().n, nonces)
        session['challenge'] = str(challenge)
        session['certificate'] = project_utils.to_b64(serializeCert(cert))
        return project_utils.json_response({"challenge": challenge}, 200)


@app.route('/validate_challenge', methods=['POST'], strict_slashes=False)
@project_utils.catch_error
def validate_challenge():
    global nonces
    response = request.get_json(force=True)
    response = response['response']
    cert = session['certificate']
    pk = cert.public_key()
    validate = verifySignature(pk, response, int(session['challenge']), cert.signature_hash_algorithm)
    if not validate:
        return project_utils.json_response({"msg": "Challenge validation failed"}, 400)
    else:
        if int(session['challenge']) in nonces:
            return project_utils.json_response({"msg": "Nonce reuse"}, 400)
        else:
            if len(nonces) >= nonce_list_lim:
                nonces = set()
                app.config['SECRET_KEY'] = uuid.uuid4().hex
            nonces.add(int(session['challenge']))
            _keys = [_key for _key in session.keys()]
            [session.pop(key) for key in _keys]
            subject_data = cert.extensions[0].value.value
            session.permanent = True
            session['subject'] = project_utils.to_b64(subject_data)
            subject_data = json.loads(subject_data)
            return project_utils.json_response({"subject": subject_data}, 200)


@app.route('/status', methods=['GET'], strict_slashes=False)
@project_utils.catch_error
def get_status():
    if 'subject' in session:
        return project_utils.json_response({"msg": "Authenticated"}, 200)
    elif 'challenge' in session:
        return project_utils.json_response({"msg": "Challenging"}, 200)
    else:
        return project_utils.json_response({"msg": "Not authenticated"}, 200)


@app.route('/', methods=['GET'])
def index():
    res = Response("Hello world", 200)
    return res


if __name__ == '__main__':
    # password = input("Password for server certificate's private key\n>>")
    password = sys.argv[1]
    context = getSSLContext('./volume/server_cert.pem', './server_key.pem', password)
    ca_cert = readCertificate('./volume/ca_cert.pem')
    app.run(host="0.0.0.0", port="5001", ssl_context=context)
