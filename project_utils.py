import base64
import flask
import json
import os


def from_b64(msg):
    decoded = base64.b64decode(msg)
    return decoded


def to_b64(msg):
    encoded = base64.b64encode(msg.encode())
    return encoded


def json_response(msg_dict, status_code):
    res = flask.Response(json.dumps(msg_dict, default=str), status=status_code, mimetype='application/json')
    return res


def get_nonce(key_size, modulus):
    while True:
        # https://cryptography.io/en/latest/random-numbers/?highlight=random
        nonce = int.from_bytes(os.urandom(key_size // 8), byteorder='big')
        if nonce < modulus:
            break
    return nonce
