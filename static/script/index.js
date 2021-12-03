function main() {
    status_msg = status();
    if (status_msg.msg == "Authenticated") {
        window.location.href = "/mypage";
    } else if (status_msg.msg == "Not authenticated" ) {
        var subject = localStorage.getItem('cert');
        if (subject == null) {
            window.location.href = "/static/html/registration.html";
            return true;
        } else {
            window.location.href = "/static/html/log_in.html";
            return true;
            }
        }
    }
}

