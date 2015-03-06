function showHidePass(event) {
    "use strict";
    var elem = $(event.target).parent().parent().find(".hidden-toggle");
    if (elem.hasClass("password-hidden")) {
        elem.removeClass("password-hidden");
        $(event.target).text("Hide");
    } else {
        elem.addClass("password-hidden");
        $(event.target).text("Show");
    }
}

function deleteEntry(e, entry_id, account_name) {
    "use strict";
    if (confirm("OK to delete entry for account " + account_name + "?")) {
        console.log("Deleting entry with ID " + entry_id);
        $.ajax({
            url: "/entries/" + entry_id,
            method: "DELETE",
            success: function (result, textStatus, obj) {
                window.location.href = "/entries/post_delete/" + account_name;
            }
        }).error(function (obj, textStatus, textCode) {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
    }
}

/**
 * From this SOF thread:
 * https://stackoverflow.com/questions/985272/selecting-text-in-an-element-akin-to-highlighting-with-your-mouse
 */
function selectText(element) {
    "use strict";
    var doc = document;
    var text = element;
    var range, selection;
    if (doc.body.createTextRange) {
        range = document.body.createTextRange();
        range.moveToElementText(text);
        range.select();
    } else if (window.getSelection) {
        selection = window.getSelection();
        range = document.createRange();
        range.selectNodeContents(text);
        selection.removeAllRanges();
        selection.addRange(range);
    }
}

function deselectText () {
    var doc = document, range, selection;
    if (doc.body.createTextRange) {
        range = document.body.createTextRange();
        range.select();
    } else if (window.getSelection) {
        selection = window.getSelection();
        selection.removeAllRanges();
    }
}

$(function() {
    "use strict";
    var timer = new LogoutTimer();
    timer.startLogoutTimer();

    $("#entry-container").click(function() {
        timer.resetLogoutTimer();
    });

    $(".hidden-toggle").click(function (e) {
        var elem = $(this);
        if (elem.hasClass("selected")) {
            deselectText();
            elem.removeClass("selected");
            elem.focus();
            elem.select();
        } else {
            selectText(this);
            elem.addClass("selected");
        }
    });

    window.onfocus = function () {
        timer.checkLogoutTimer();
    };
});
