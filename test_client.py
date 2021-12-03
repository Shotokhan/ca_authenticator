import requests
from certificates_library import genKeyPair, createCSR, readKey, readCertificate, signCertificateRequest, makeSignature,\
    readConfigFromJSON, verifySignature, loadCertificate
from project_utils import to_b64, from_b64
import json
import urllib3
import re


urllib3.disable_warnings()


def keycloak_login(session, url):
    res = session.get(url + '/api/keycloak_login', verify=False)
    pat = re.compile("""http://.*/auth/realms/.*/login-actions/authenticate?.*method""")
    next_url = re.findall(pat, res.text)
    next_url = next_url[0]
    next_url = next_url[:next_url.index('"')]
    next_url = next_url.replace('amp;', '')
    authN = session.post(next_url, data={'username': 'prova', 'password': 'prova', 'credentialId': ''},
                         verify=False)
    # everything is done with redirections
    print(authN.text)
    assert authN.url == url + '/api/keycloak_login'


def local_registration():
    key = genKeyPair('./test/client_key.pem', 'prova')
    subject = readConfigFromJSON('./volume/client_data.json')
    csr, _ = createCSR(subject, key)
    ca_key = readKey('./test/ca_key.pem', 'prova')
    ca_cert = readCertificate('./test/ca_cert.pem')
    client_cert, client_cert_ser = signCertificateRequest(csr, ca_cert, ca_key, 7)
    return client_cert, client_cert_ser, key


def remote_registration(session, url):
    key = genKeyPair('./test/client_key.pem', 'prova')
    subject = readConfigFromJSON('./volume/client_data.json')
    csr, csr_ser = createCSR(subject, key)
    registration_request = {'csr': to_b64(csr_ser), 'validity_days': subject['VALIDITY_DAYS']}
    response = session.post(url + "/api/registration", json=registration_request, verify=False)
    if response.status_code == 200:
        client_cert_ser = from_b64(json.loads(response.text)['cert'])
        client_cert = loadCertificate(client_cert_ser)
        print(client_cert.signature)
        return client_cert, client_cert_ser, key
    else:
        print(response.text)
        exit(1)


def test_correct_authentication(authentication_url, local=True, registration_url=None):
    session = requests.Session()
    keycloak_login(session, authentication_url)
    if local:
        client_cert, client_cert_ser, key = local_registration()
    else:
        client_cert, client_cert_ser, key = remote_registration(session, registration_url)
    auth_request = {'cert': to_b64(client_cert_ser)}
    response = session.post(authentication_url + "/api/authenticate", json=auth_request, verify=False)
    if response.status_code == 200:
        challenge = from_b64(json.loads(response.text)['challenge'])
        print(int.from_bytes(challenge, 'big'))
        pk = client_cert.public_key()
        validation = makeSignature(key, challenge, client_cert.signature_hash_algorithm)
        validation = to_b64(validation)

        server_validation = from_b64(validation)
        assert verifySignature(pk, server_validation, challenge, client_cert.signature_hash_algorithm)

        validate_challenge = {'response': validation}
        response = session.post(authentication_url + "/api/validate_challenge", json=validate_challenge, verify=False)
        if response.status_code == 200:
            subject = json.loads(response.text)
            print(subject)
            status = session.get(authentication_url + "/api/status", verify=False)
            print(json.loads(status.text)['msg'])
            print(session.cookies)
            print(f"Correct authentication with {'local' if local else 'remote'} registration")
        else:
            print(response.text)
    else:
        print(response.text)


if __name__ == "__main__":
    print("WARNING: make sure you have configured well Keycloak.")
    print("You should have an user with username 'prova' and password 'prova', and all the related configurations.")
    inp = input("Did you check all the configurations? [y/N]\n")
    if inp.strip() != 'y':
        exit(1)
    test_correct_authentication("https://127.0.0.1:5001")
    print()
    test_correct_authentication(authentication_url="https://127.0.0.1:5001", local=False, registration_url="https://127.0.0.1:5001")

