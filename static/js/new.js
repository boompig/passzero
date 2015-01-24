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
        //elem.parent().find("#gen-pass-btn").prop({"disabled": false});
    } else {
        elem.attr("type", "password");
        $(event.target).text("Show");
        //elem.parent().find("#gen-pass-btn").prop({"disabled": true});
    }
}

function createNew (e) {
    "use strict";
    e.preventDefault();

    var dataArray = $(e.target).serializeArray();
    var url = $(e.target).attr("action");
    var data = parseArray(dataArray);

    $.post(url, data, function(response) {
        window.location.href = "/entries/done_new/" + data.account;
    }, "json");
    return false;
}

function makeEdit (e) {
    "use strict";
    e.preventDefault();

    var elem = $(e.target);
    var url = elem.attr("action");
    var dataArray = elem.serializeArray();
    var data = parseArray(dataArray);

    $.post(url, data, function (response) {
        window.location.href = "/entries/done_edit/" + data.account;
    }, "json");

    return false;
}
