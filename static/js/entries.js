var restart = true;
var val = 0;
var maxVal = 4 * 60;

function showHidePass(event) {
    var elem = $(event.target).parent().find(".password");
    var t = elem.attr("type");
    if (t === "password") {
        elem.attr("type", "text");
        $(event.target).text("Hide");
    } else {
        elem.attr("type", "password");
        $(event.target).text("Show");
    }
}

function resetLogoutTimer() {
    restart = true;
    console.log("restart");
}

function startLogoutTimer() {
    // for debugging
    if (val % 10 === 0) console.log(val);

    if (restart) {
        val = maxVal;
        restart = false;
    } else {
        if (val <= 0) {
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
