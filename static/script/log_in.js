var lnkSubmit = document.forms.formlogin;
function formSubmit_login() {
    var subject = localStorage.getItem('cert');
    authenticate_msg = authenticate(subject);
    if (authenticate_msg.status == 200) {
        var pair = localStorage.getItem('enc_pair');
        var password = lnkSubmit.password.value;
        k = readKey(pair.privateKeyEnc, password);
        pair.privateKey = k;
        challenge_b64 = authenticate_msg.challenge;
        validate_challenge_msg = validate_challenge(pair.privateKey, challenge_b64);
        status_msg = status();
        if (status_msg.msg == "Authenticated") {
            window.location.href = "/mypage";
            return true;
        } else {
            window.location.href = "/static/html/registration.html";
            return true;
        }
    }

}





