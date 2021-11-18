from flask import Flask, Response, request
from certificates_library import getSSLContext, readCertificate, readKey, loadCSR, signCertificateRequest
import sys
import project_utils


app = Flask(__name__, static_folder="/usr/src/app/volume/")
server_pass, ca_pass = sys.argv[1], sys.argv[2]
ca_cert = readCertificate('./volume/ca_cert.pem')
ca_key = readKey('./ca_key.pem', ca_pass)


@app.route('/registration', methods=['POST'], strict_slashes=False)
@project_utils.catch_error
def registration():
    # {"csr": base64(csr), "validityDays": int}
    req = request.get_json(force=True)
    csr = project_utils.from_b64(req['csr'])
    validity_days = req['validity_days']
    validity_days = project_utils.filter_validity_days(validity_days)
    try:
        csr = loadCSR(csr)
    except AssertionError:
        return project_utils.json_response({"msg": "CSR validation failed"}, 400)
    # TODO: validate extensions based on 3rd party authentication
    _, client_cert_ser = signCertificateRequest(csr, ca_cert, ca_key, validity_days)
    client_cert_ser = project_utils.to_b64(client_cert_ser)
    return project_utils.json_response({"cert": client_cert_ser}, 200)


@app.route('/', methods=['GET'])
def index():
    res = Response("Hello world", 200)
    return res


if __name__ == '__main__':
    # password = input("Password for CA certificate's private key\n>>")
    context = getSSLContext('./volume/server_cert.pem', './server_key.pem', server_pass)
    app.run(host="0.0.0.0", port="5002", ssl_context=context)
