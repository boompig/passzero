/* for passphrase generation */
var words = [];
var dictionary = "common.txt";

/* settings */
var showSettings = false;
var genSpecialChars = true;
var maxNumWords = 10;

var timer = null;

function showHideSettings () {
    $("#len-container").toggle();
}

/**
 * Get a random integer in interval [a, b)
 */
function randInt(a, b) {
    return Math.floor(Math.random() * (b - a) + a);
}

function genPassphraseHelper() {
    "use strict";
    var phrase = "", index, word;
    var numWords = Number($("#phraseLen").text());
    for (var i = 0; i < numWords; i++) {
        index = Math.floor(Math.random() * words.length);
        word = words[index];
        word = word[0].toUpperCase() + word.substr(1);
        phrase += word;
    }
    setPassword(phrase);

}

function setPassword(pass) {
    $("#password").val(pass).keyup();
    if ($("#password").attr("type") == "password") {
        showHidePassword();
    }
}

function genPassphrase () {
    "use strict";
    if (words.length === 0) {
        $.get("/dictionary/" + dictionary, function (response) {
            words = response.split("\n").filter(function (w) {
                return w.length >= 5;
            });

            genPassphraseHelper();
        });
    } else {
        genPassphraseHelper();
    }
    return 0;
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

    for (i = 0; i < length; i++) {
        passArray[i] = chars[randInt(0, chars.length)];
    }

    var pass = passArray.join("");
    setPassword(pass);
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

/**
 * Called to submit form data to server
 * Creates a new entry
 * On success does a redirect
 */
function createNew (e) {
    "use strict";
    e.preventDefault();

    var url = $(e.target).attr("action");
    var data = getFormData(e.target);

    pzAPI.createEntry(data, data.csrf_token)
    .done(function(response) {
        window.location.href = "/entries/done_new/" + data.account;
    }).error(function (obj, textStatus, textCode) {
        console.log(obj);
        console.log(textStatus);
        console.log(textCode);
    });
    return false;
}

function getEntryID() {
    var components = window.location.href.split("/");
    return components[components.length - 1];
}

function makeEdit (e) {
    "use strict";
    e.preventDefault();
    var data = getFormData(e.target);
    var entry_id = getEntryID();
    pzAPI.editEntry(entry_id, data, data.csrf_token)
    .done(function(response) {
        window.location.href = "/entries/done_edit/" + data.account;
    });
    return false;
}

function changeLen(diff) {
    "use strict";
    var elem = $("#passLen");
    var len = Number(elem.text());
    elem.text(len + diff);
}

function changePhraseLen(diff) {
    "use strict";
    var elem = $("#phraseLen");
    var len = Number(elem.text());
    if (len + diff > 0 && len + diff <= maxNumWords) {
        elem.text(len + diff);
    }
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

    // set in globals (declared at top)
    timer = new LogoutTimer();
    timer.startLogoutTimer();
    $("form").click(function () {
        timer.resetLogoutTimer();
    });
    $("form").keydown(function() {
        timer.resetLogoutTimer();
    });
    window.onfocus = function () {
        timer.checkLogoutTimer();
    };
});
