from flask import Flask, Response, request, session
from certificates_library import getSSLContext, loadCertificate, readCertificate, verifyCertificate, serializeCert
import sys
import project_utils
import uuid
from datetime import timedelta


app = Flask(__name__, static_folder="/usr/src/app/volume/")
app.config['SECRET_KEY'] = uuid.uuid4().hex
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
ca_cert = None


@app.route('/authenticate', methods=['POST'], strict_slashes=False)
def authenticate():
    # {"cert": base64(cert)}
    cert = request.get_json(force=True)
    cert = project_utils.from_b64(cert['cert'])
    cert = loadCertificate(cert)
    valid = verifyCertificate(ca_cert, cert)
    if not valid:
        return project_utils.json_response({"msg": "Certificate validation failed"}, 400)
    else:
        pk = cert.public_key()
        challenge = project_utils.get_nonce(pk.key_size, pk.public_numbers().n)
        session['challenge'] = str(challenge)
        session['certificate'] = project_utils.to_b64(serializeCert(cert))
        return project_utils.json_response({"challenge": challenge}, 200)


@app.route('/', methods=['GET'])
def index():
    res = Response("Hello world", 200)
    return res


if __name__ == '__main__':
    # password = input("Password for server certificate's private key\n>>")
    password = sys.argv[1]
    context = getSSLContext('./volume/server_cert.pem', './server_key.pem', password)
    ca_cert = readCertificate('./volume/ca_cert.pem')
    # TODO: require client certificate
    app.run(host="0.0.0.0", port="5001", ssl_context=context)
