function endpoint_button_stub(endpoint) {
    msg = endpoint_call_stub(endpoint);
    alert(msg.msg);
}

function weak_logout() {
    logout();
    window.location.href = "/goodbye";
}

function strong_logout() {
    logout();
    localStorage.clear();
    window.location.href = "/goodbye";
}
