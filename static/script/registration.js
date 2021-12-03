function formSubmit_registrazione() {
    var city = '{ "IT": "Italia", "ES": "Spagna", "UK": "Regno Unito", "US": "Stati Uniti", "FR": "Francia" }';
    city = JSON.parse(city);
    var username = document.formRegistration.username.value;
    var password = document.formRegistration.password.value;
    var conferma = document.formRegistration.conferma.value;
    var countryName = document.formRegistration.paese.options[document.formRegistration.paese.selectedIndex].value;
    var localityName = document.formRegistration.citta.options[document.formRegistration.citta.selectedIndex].value;
    var organization_name = document.formRegistration.organization_name.value;
    var role = document.formRegistration.role.options[document.formRegistration.role.selectedIndex].value;
    if (password != conferma) {
        alert("La password confermata è diversa da quella scelta, controllare.");
        document.formRegistration.conferma.value = "";
        document.formRegistration.conferma.focus();
        return false;
    }
    stateOrProvinceName = city[countryName];
    pair = genKeyPair(password);
    localStorage.setItem('enc_pair', pair)
    k = readKey(pair.privateKeyEnc, password);
    pair.privateKey = k;
    subject = { "COUNTRY_NAME": countryName, "STATE_OR_PROVINCE_NAME": stateOrProvinceName, "LOCALITY_NAME": localityName, "ORGANIZATION_NAME": organization_name, "VALIDITY_DAYS": 3, "EXTENSION": { "id": username, "role": role } };
    csr_pem = createCSR(subject, pair);
    registration_msg = registration(csr_pem, subject);
    if (registration_msg.status == 200) {
        cert = atob(registration_msg.cert);
        localStorage.setItem('cert', cert);
        window.location.href = "/static/html/log_in.html";
        return true;
        }
    } else {
        alert('Registration failed');
        return false;
    }
}