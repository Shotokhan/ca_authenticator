function main() {
    status_msg = status();
    if (status_msg.msg == "Authenticated") {
        window.location.href = "/my_page";
    } else if (status_msg.msg == "Not authenticated" ) {
        var subject = localStorage.getItem('cert');
        if (subject == null) {
            window.location.href = "/registration";
            return true;
        } else {
            window.location.href = "/login";
            return true;
        }
    }
}

