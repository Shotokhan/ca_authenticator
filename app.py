from flask import Flask, Response
from certificates_library import getSSLContext
import sys


app = Flask(__name__, static_folder="/usr/src/app/volume/")


@app.route('/', methods=['GET'])
def index():
    res = Response("Hello world", 200)
    return res


if __name__ == '__main__':
    # password = input("Password for server certificate's private key\n>>")
    password = sys.argv[1]
    context = getSSLContext('./volume/server_cert.pem', './server_key.pem', password)
    # TODO: require client certificate
    app.run(host="0.0.0.0", port="5001", ssl_context=context)
