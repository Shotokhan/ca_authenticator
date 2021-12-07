function formSubmit_registrazione() {
    var country_mappings = '{ "IT": "Italia", "ES": "Spagna", "UK": "Regno Unito", "US": "Stati Uniti", "FR": "Francia" }';
    country_mappings = JSON.parse(country_mappings);
    var username = document.formRegistration.username.value;
    var password = document.formRegistration.password.value;
    var conferma = document.formRegistration.conferma.value;
    var countryName = document.formRegistration.paese.options[document.formRegistration.paese.selectedIndex].value;
    var localityName = document.formRegistration.citta.options[document.formRegistration.citta.selectedIndex].value;
    var organization_name = document.formRegistration.organization_name.value;
    var role = document.formRegistration.role.options[document.formRegistration.role.selectedIndex].value;
    var validity_days = document.formRegistration.validity_days.value;
    if (password != conferma) {
        alert("Passwords don't match");
        document.formRegistration.conferma.value = "";
        document.formRegistration.conferma.focus();
        return false;
    }
    let strongPassword = new RegExp('(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})')

    if(!strongPassword.test(password)) {
        alert('Select a strong password');
    }

    stateOrProvinceName = country_mappings[countryName];
    pair = genKeyPair(password);
    localStorage.setItem('enc_key', pair.privateKeyEnc)
    k = readKey(pair.privateKeyEnc, password);
    pair.privateKey = k;
    subject = { "COUNTRY_NAME": countryName, "STATE_OR_PROVINCE_NAME": stateOrProvinceName, "LOCALITY_NAME": localityName, "ORGANIZATION_NAME": organization_name, "VALIDITY_DAYS": validity_days, "EXTENSION": { "id": username, "role": role } };
    csr_pem = createCSR(subject, pair);
    registration_msg = registration(csr_pem, subject);
    if (registration_msg.status == 200) {
        cert = atob(registration_msg.cert);
        localStorage.setItem('cert', cert);
        window.location.href = "/login";
        return true;
    } else {
        alert('Registration failed');
        return false;
    }
}
