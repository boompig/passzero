/**
 * Generate a random password
 */
function genPassword() {
    "use strict";
    var length = $("#passLen").val();
    var passArray = [];
    var bannedChars = ['"', "'", "\\"];
    var charCode;

    for(var i = 0; i < length; i++) {
        do {
            charCode = Math.round(Math.random() * (122 - 33) + 33);
            passArray[i] = String.fromCharCode(charCode);
        } while (bannedChars.indexOf(passArray[i]) >= 0);
    }

    var pass = passArray.join("");
    $("#password").val(pass);
    return 0;
}

function showHidePassword(event) {
    var elem = $("#password");
    var t = elem.attr("type");
    if (t === "password") {
        elem.attr("type", "text");
        $(event.target).text("Hide");
        elem.parent().find("#gen-pass-btn").prop({"disabled": false});
    } else {
        elem.attr("type", "password");
        $(event.target).text("Show");
        elem.parent().find("#gen-pass-btn").prop({"disabled": true});
    }
}
