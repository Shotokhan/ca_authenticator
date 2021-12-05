from flask import Flask, Response, request, session, render_template, send_from_directory, redirect
from flask_oidc import OpenIDConnect
from certificates_library import getSSLContext, loadCertificate, readCertificate, verifyCertificate, serializeCert, \
    verifySignature, readKey, signCertificateRequest, loadCSR
import sys
import project_utils
import uuid
import json
from datetime import timedelta
import mongo_utils


app = Flask(__name__, static_folder="/usr/src/app/static/", template_folder="/usr/src/app/static/html/")
server_pass, ca_pass = sys.argv[1], sys.argv[2]
ca_cert = readCertificate('./volume/ca_cert.pem')
ca_key = readKey('./volume/ca_key.pem', ca_pass)
with open('./volume/config/config.json', 'r') as f:
    config = json.load(f)
app.config['SECRET_KEY'] = uuid.uuid4().hex
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config.update(config['app'])
nonces = set()
nonce_list_lim = config['misc']['nonce_list_lim']
mongo_client = mongo_utils.open_client(config['mongo']['url'])
if config['misc']['disable_ssl_verification_for_oauth2']:
    project_utils.disable_ssl_verification_oauth2_client()

oidc = OpenIDConnect(app)


def endpoint_stub(session, resource):
    if 'subject' in session:
        global mongo_client
        global config
        decision = project_utils.access_control(session, mongo_client, config, resource)
        if decision:
            return project_utils.json_response({"msg": "Allowed"}, 200)
        else:
            return project_utils.json_response({"msg": "Unauthorized"}, 401)
    else:
        return project_utils.json_response({"msg": "Not authenticated"}, 400)


@app.route('/api/authenticate', methods=['POST'], strict_slashes=False)
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
        challenge = project_utils.to_b64(challenge.to_bytes(pk.key_size, byteorder='big'))
        session['challenge'] = challenge
        session['certificate'] = project_utils.to_b64(serializeCert(cert))
        return project_utils.json_response({"challenge": challenge}, 200)


@app.route('/api/validate_challenge', methods=['POST'], strict_slashes=False)
@project_utils.catch_error
def validate_challenge():
    global nonces
    cert = loadCertificate(project_utils.from_b64(session['certificate']))
    pk = cert.public_key()
    response = request.get_json(force=True)
    response = response['response']
    response = project_utils.from_b64(response)
    challenge = project_utils.from_b64(session['challenge'])
    validate = verifySignature(pk, response, challenge, cert.signature_hash_algorithm)
    if not validate:
        return project_utils.json_response({"msg": "Challenge validation failed"}, 400)
    else:
        if challenge in nonces:
            return project_utils.json_response({"msg": "Nonce reuse"}, 400)
        else:
            if len(nonces) >= nonce_list_lim:
                nonces = set()
                app.config['SECRET_KEY'] = uuid.uuid4().hex
            nonces.add(int.from_bytes(challenge, byteorder='big'))
            _keys = [_key for _key in session.keys()]
            [session.pop(key) for key in _keys]
            subject_data = cert.extensions[0].value.value
            session.permanent = True
            session['subject'] = project_utils.to_b64(subject_data)
            subject_data = project_utils.subject_data_from_json(subject_data)
            return project_utils.json_response({"subject": subject_data}, 200)


@app.route('/api/status', methods=['GET'], strict_slashes=False)
@project_utils.catch_error
def get_status():
    if 'subject' in session:
        return project_utils.json_response({"msg": "Authenticated"}, 200)
    elif 'challenge' in session:
        return project_utils.json_response({"msg": "Challenging"}, 200)
    else:
        return project_utils.json_response({"msg": "Not authenticated"}, 200)


@app.route('/api/registration', methods=['POST'], strict_slashes=False)
@oidc.require_login
@project_utils.catch_error
def registration():
    # {"csr": base64(csr), "validityDays": int}
    global mongo_client
    global config
    req = request.get_json(force=True)
    csr = project_utils.from_b64(req['csr'])
    validity_days = req['validity_days']
    validity_days = project_utils.filter_validity_days(validity_days, config['misc']['max_validity_days'])
    try:
        csr = loadCSR(csr)
    except AssertionError:
        return project_utils.json_response({"msg": "CSR validation failed"}, 400)
    client_cert, client_cert_ser = signCertificateRequest(csr, ca_cert, ca_key, validity_days)
    ext = json.loads(client_cert.extensions[0].value.value.decode().replace('\\', ''))
    username, role, resources = project_utils.get_oidc_info(oidc)
    if username == ext['id'] and role == ext['role']:
        data = {'role': role, 'resources': resources}
        mongo_utils.insert_or_update(mongo_client, config['mongo']['db_name'], config['mongo']['collection_name'], data)
        client_cert_ser = project_utils.to_b64(client_cert_ser)
        oidc.logout()
        return project_utils.json_response({"cert": client_cert_ser}, 200)
    else:
        return project_utils.json_response({"msg": "Invalid credentials"}, 400)


@app.route('/api/logout', methods=['GET'], strict_slashes=False)
@project_utils.catch_error
def logout():
    _keys = [_key for _key in session.keys()]
    [session.pop(key) for key in _keys]
    return project_utils.json_response({"msg": "Logout successful"}, 200)


@app.route('/api/keycloak_login', methods=['GET'], strict_slashes=False)
@oidc.require_login
@project_utils.catch_error
def keycloak_login():
    username, role, resources = project_utils.get_oidc_info(oidc)
    msg = f"Username {username} with role {role} can access: {', '.join(resources)}"
    return project_utils.json_response({"msg": msg}, 200)


@app.route('/api/view_exam', methods=['GET'], strict_slashes=False)
@project_utils.catch_error
def view_exam_stub():
    return endpoint_stub(session, 'view-exam')


@app.route('/api/book_exam', methods=['GET'], strict_slashes=False)
@project_utils.catch_error
def book_exam_stub():
    return endpoint_stub(session, 'book-exam')


@app.route('/api/view_grade', methods=['GET'], strict_slashes=False)
@project_utils.catch_error
def view_grade_stub():
    return endpoint_stub(session, 'view-grade')


@app.route('/api/publish_exam', methods=['GET'], strict_slashes=False)
@project_utils.catch_error
def publish_exam_stub():
    return endpoint_stub(session, 'publish-exam')


@app.route('/api/confirm_exam', methods=['GET'], strict_slashes=False)
@project_utils.catch_error
def confirm_exam_stub():
    return endpoint_stub(session, 'confirm-exam')


@app.route('/', methods=['GET'])
@project_utils.catch_error
def index():
    return render_template('index.html')


@app.route('/registration', methods=['GET'])
@oidc.require_login
@project_utils.catch_error
def registration_page():
    return render_template('registration.html')


@app.route('/login', methods=['GET'])
@project_utils.catch_error
def login_page():
    return render_template('login.html')


@app.route('/goodbye', methods=['GET'])
@project_utils.catch_error
def goodbye_page():
    return render_template('goodbye.html')


@app.route('/my_page', methods=['GET'])
@project_utils.catch_error
def page_for_user():
    if 'subject' in session:
        global mongo_client
        global config
        subject_data = project_utils.from_b64(session['subject'])
        subject_data = project_utils.subject_data_from_json(subject_data)
        username, role = subject_data['id'], subject_data['role']
        resources = mongo_utils.get_resources_from_role(mongo_client, config['mongo']['db_name'], config['mongo']['collection_name'], {'role': role})
        rest_api_resources = config['rest_resources']
        return render_template('my_page.html', username=username, role=role, resources=resources,
                               endpoints=rest_api_resources)
    else:
        return redirect("/", 302)


@app.route('/favicon.ico', methods=['GET'])
@project_utils.catch_error
def favicon():
    return send_from_directory("/usr/src/app/static", "you_shall_not_pass.jpg", mimetype='image/jpg')


if __name__ == '__main__':
    # password = input("Password for server certificate's private key\n>>")
    context = getSSLContext('./volume/server_cert.pem', './volume/server_key.pem', server_pass)
    app.run(host="0.0.0.0", port="5001", ssl_context=context)
