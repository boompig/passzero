var restart = true;
var val = 0;
var maxVal = 5 * 60;

function showHidePass(event) {
    var elem = $(event.target).parent().find(".password");
    console.log(elem);
    var t = elem.attr("type");
    if (t === "password") {
        elem.attr("type", "text");
        $(event.target).text("Hide");
    } else {
        elem.attr("type", "password");
        $(event.target).text("Show");
    }
}

function startLogoutTimer() {
    if (restart) {
        val = maxVal;
        restart = false;
    } else {
        if (val === 0) {
            // logout
            window.location.href = "/logout";
        } else {
            val--;
        }
    }

    setTimeout(startLogoutTimer, 1000);
}

$(function() {
    startLogoutTimer();
});
