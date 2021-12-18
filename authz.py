import requests
import re
import json


class AuthorizationContext:
    def __init__(self, token_uri, scope, audience, client_secret, verify_https):
        self.token_uri = token_uri
        self.scope = scope
        self.audience = audience
        self.grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket"
        self.client_secret = client_secret
        self.verify_https = not verify_https
        self.access_token_pat = re.compile(r"^[\w\-_]+[.][\w\-_]+[.][\w\-_]+$")

    def check_permission(self, access_token, resource):
        # decision is actually made by Keycloak: if permission is not allowed,
        # the access token is not returned; instead it is returned something like:
        # {"error":"access_denied","error_description":"not_authorized"}
        if re.match(self.access_token_pat, access_token) is None:
            return False
        else:
            try:
                authz_token = self.get_authz_token(access_token, resource)
                if 'access_token' in authz_token:
                    return True
                else:
                    return False
            except:
                return False

    def get_authz_token(self, access_token, resource):
        headers = {"Authorization": f"Bearer {access_token}"}
        data = {"grant_type": self.grant_type, "audience": self.audience,
                "permission": f"{resource}#{self.scope}"}
        response = requests.post(self.token_uri, data=data, headers=headers, verify=self.verify_https)
        res = json.loads(response.text)
        return res

    def new_access_token(self, refresh_token):
        try:
            return self.refresh_access_token(refresh_token), True
        except:
            return None, False

    def refresh_access_token(self, refresh_token):
        data = {"client_id": self.audience, "client_secret": self.client_secret,
                "grant_type": "refresh_token", "refresh_token": refresh_token}
        response = requests.post(self.token_uri, data=data, verify=self.verify_https)
        res = json.loads(response.text)
        return res['access_token']
