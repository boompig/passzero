var genSpecialChars = true;

/**
 * Get a random integer in interval [a, b)
 */
function randInt(a, b) {
    return Math.floor(Math.random() * (b - a) + a);
}

/**
 * Generate a random password
 */
function genPassword() {
    "use strict";
    var length = $("#passLen").text();
    var i;
    var passArray = [];
    var chars = [];
    for (i = "a".charCodeAt(0); i <= "z".charCodeAt(0); i++) {
        chars.push(String.fromCharCode(i));
    }
    for (i = "A".charCodeAt(0); i <= "Z".charCodeAt(0); i++) {
        chars.push(String.fromCharCode(i));
    }
    for (i = "0".charCodeAt(0); i <= "9".charCodeAt(0); i++) {
        chars.push(String.fromCharCode(i));
    }
    if (genSpecialChars) {
        for (i = "!".charCodeAt(0); i <= "/".charCodeAt(0); i++) {
            chars.push(String.fromCharCode(i));
        }
    }

    for(var i = 0; i < length; i++) {
        passArray[i] = chars[randInt(0, chars.length)];
    }

    var pass = passArray.join("");
    $("#password").val(pass).keyup();

    if ($("#password").attr("type") == "password") {
        showHidePassword();
    }

    return 0;
}

function showHidePassword(e) {
    "use strict";
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
    "use strict";
    if (on) {
        $("#len-container").show();
        $("#gen-pass-btn").prop({ disabled: false });
    } else {
        $("#len-container").hide();
        $("#gen-pass-btn").prop({ disabled: true });
    }
}

function toggleSpecialChar(e) {
    "use strict";
    genSpecialChars = !genSpecialChars;
    console.log(e);
    if (genSpecialChars) {
        $(e.currentTarget).addClass("active");
    } else {
        $(e.currentTarget).removeClass("active");
    }
}

$(function() {
    "use strict";

    if ($("#password").val().length > 0) {
        togglePasswordGen(false);
    } else {
        $("#show-hide-btn").prop({ disabled: true });
    }

    $("#toggleSymbols").click(function (e) {
        toggleSpecialChar(e);
    });

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
