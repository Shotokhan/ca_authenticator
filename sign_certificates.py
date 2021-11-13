from flask import Flask, Response
from certificates_library import getSSLContext, readCertificate, readKey
import sys


app = Flask(__name__, static_folder="/usr/src/app/volume/")


@app.route('/', methods=['GET'])
def index():
    res = Response("Hello world", 200)
    return res


if __name__ == '__main__':
    # password = input("Password for CA certificate's private key\n>>")
    server_pass, ca_pass = sys.argv[1], sys.argv[2]
    context = getSSLContext('./volume/server_cert.pem', './server_key.pem', server_pass)
    ca_cert = readCertificate('./volume/ca_cert.pem')
    ca_key = readKey('./ca_key.pem', ca_pass)
    app.run(host="0.0.0.0", port="5002", ssl_context=context)
