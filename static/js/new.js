/**
 * Generate a random password
 */
function genPassword() {
    "use strict";
    var length = $("#passLen").text();
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
    $("#password").val(pass).keyup();

    if ($("#password").attr("type") == "password") {
        showHidePassword();
    }

    return 0;
}

function showHidePassword(e) {
    var elem = $("#password");
    var t = elem.attr("type");
    if (t === "password") {
        elem.attr("type", "text");
        $("#show-hide-btn").text("Hide");
        togglePasswordGen(true);
    } else {
        elem.attr("type", "password");
        $("#show-hide-btn").text("Show");
        togglePasswordGen(false);
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
    }, "json").error(function (obj, textStatus, textCode) {
        console.log(obj);
        console.log(textStatus);
        console.log(textCode);
    });
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

function changeLen(diff) {
    "use strict";
    var elem = $("#passLen");
    var len = Number(elem.text());
    elem.text(len + diff);
}

function togglePasswordGen(on) {
    if (on) {
        $("#len-container").show();
        $("#gen-pass-btn").prop({ disabled: false });
    } else {
        $("#len-container").hide();
        $("#gen-pass-btn").prop({ disabled: true });
    }
}

$(function() {
    "use strict";

    if ($("#password").val().length > 0) {
        togglePasswordGen(false);
    } else {
        $("#show-hide-btn").prop({ disabled: true });
    }

    $("#password").keyup(function () {
        if ($(this).val().length > 0) {
            $("#show-hide-btn").prop({ disabled: false });
            if ($("#show-hide-btn").text() === "Show") {
                togglePasswordGen(false);
            }
        } else {
            $("#show-hide-btn").prop({ disabled: true });
        }
    });
});
