import requests
from certificates_library import genKeyPair, createCSR, readKey, readCertificate, signCertificateRequest, makeSignature
from project_utils import to_b64
import json


def test_correct_authentication(url):
    key = genKeyPair('./test/client_key.pem', 'prova')
    subject = {'id': 'michele', 'role': 'studente'}
    csr, _ = createCSR(subject, key)
    ca_key = readKey('./test/ca_key.pem', 'prova')
    ca_cert = readCertificate('./test/ca_cert.pem')
    client_cert, client_cert_ser = signCertificateRequest(csr, ca_cert, ca_key, 7)
    auth_request = {'cert': to_b64(client_cert_ser)}
    session = requests.Session()
    response = session.post(url + "/authenticate", json=auth_request, verify=False)
    if response.status_code == 200:
        challenge = json.loads(response.text)['challenge']
        print(challenge)
        challenge = challenge.to_bytes(challenge.bit_length(), 'little')
        validation = makeSignature(key, challenge, client_cert.signature_hash_algorithm)
        validation = int.from_bytes(validation, 'little')
        validate_challenge = {'response': validation}
        response = session.post(url + "/validate_challenge", json=validate_challenge, verify=False)
        if response.status_code == 200:
            subject = json.loads(response.text)
            print(subject)
            status = session.get(url + "/status", verify=False)
            print(json.loads(status.text)['msg'])


if __name__ == "__main__":
    test_correct_authentication("https://127.0.0.1:5001")
