function status(url) {

    var xhr = new XMLHttpRequest();

/*
    xhr.addEventListener('error', function (event) { console.log('error in status response'); });
    xhr.addEventListener('load', function (event) {
        let res = JSON.parse(xhr.responseText);
        console.log('status :' + JSON.stringify(res.msg));
    });
*/

    xhr.open('GET', url + '/status', false);
    xhr.setRequestHeader('ContentType', 'application/json');
    xhr.send();
    msg = JSON.parse(xhr.responseText);
    msg.status = xhr.status;
    return msg;

}