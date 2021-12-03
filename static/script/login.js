var lnkSubmit = document.forms.formlogin;
function formSubmit_login() {
    var subject = localStorage.getItem('cert');
    authenticate_msg = authenticate(subject);
    if (authenticate_msg.status == 200) {
        var enc_key = localStorage.getItem('enc_key');
        var password = lnkSubmit.password.value;
        var privateKey = readKey(enc_key, password);
        challenge_b64 = authenticate_msg.challenge;
        validate_challenge_msg = validate_challenge(privateKey, challenge_b64);
        status_msg = status();
        if (status_msg.msg == "Authenticated") {
            window.location.href = "/my_page";
            return true;
        } else {
            window.location.href = "/static/html/registration.html";
            return true;
        }
    }
}
