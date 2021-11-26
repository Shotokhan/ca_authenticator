function status() {

    var xhr = new XMLHttpRequest();

/*
    xhr.addEventListener('error', function (event) { console.log('error in status response'); });
    xhr.addEventListener('load', function (event) {
        let res = JSON.parse(xhr.responseText);
        console.log('status :' + JSON.stringify(res.msg));
    });
*/

    xhr.open('GET', '/status', false);
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
    xhr.open('POST', '/registration', false);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(json_request);
    msg = JSON.parse(xhr.responseText);
    msg.status = xhr.status;

    return msg;
}