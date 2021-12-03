function status() {

    var xhr = new XMLHttpRequest();

/*
    xhr.addEventListener('error', function (event) { console.log('error in status response'); });
    xhr.addEventListener('load', function (event) {
        let res = JSON.parse(xhr.responseText);
        console.log('status :' + JSON.stringify(res.msg));
    });
*/

    xhr.open('GET', '/api/status', false);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send();
    msg = JSON.parse(xhr.responseText);
    msg.status = xhr.status;
    return msg;

}

function registration(csr_pem, subject) {

    var xhr = new XMLHttpRequest();
    csr_b64 = btoa(csr_pem);
    json_request = { csr: csr_b64, validity_days: subject.VALIDITY_DAYS };
    json_request = JSON.stringify(json_request);
    xhr.open('POST', '/api/registration', false);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(json_request);
    msg = JSON.parse(xhr.responseText);
    msg.status = xhr.status;

    return msg;
}

function authenticate(cert_pem) {

    var xhr = new XMLHttpRequest();
    cert_b64 = btoa(cert_pem);
    json_request = { cert: cert_b64 };
    json_request = JSON.stringify(json_request);
    xhr.open('POST', '/api/authenticate', false);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(json_request);
    msg = JSON.parse(xhr.responseText);
    msg.status = xhr.status;

    return msg;

}

function validate_challenge(privateKey, challenge_b64) {

    var xhr = new XMLHttpRequest();
    challenge = atob(challenge_b64);
    validation = makeSignature(privateKey, challenge);
    validation_b64 = btoa(validation);
    json_request = { response: validation_b64 };
    json_request = JSON.stringify(json_request);
    xhr.open('POST', '/api/validate_challenge', false);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(json_request);
    msg = JSON.parse(xhr.responseText);
    msg.status = xhr.status;

    return msg;

}
