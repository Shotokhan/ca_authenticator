import requests
import json


def testAuthz():
    data = {"client_id": "flask-app", "client_secret": "b02e20a3-f24b-4a13-9815-5234be43f41a",
            "username": "prova", "password": "prova", "grant_type": "password"}
    token_uri = "https://10.5.0.4:8443/auth/realms/flask-demo/protocol/openid-connect/token"
    access_token = requests.post(token_uri, data=data, verify=False)
    print(access_token.text)
    access_token = json.loads(access_token.text)['access_token']
    data = {"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket", "audience": "flask-app",
            "permission": "view-exam#do"}
    headers = {"Authorization": f"Bearer {access_token}"}
    decision = requests.post(token_uri, data=data, headers=headers, verify=False)
    print(decision.text)


if __name__ == "__main__":
    testAuthz()
