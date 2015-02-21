function showHidePass(event) {
    var elem = $(event.target).parent().parent().find(".password");
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

$(function() {
    "use strict";
    var timer = new LogoutTimer();
    timer.startLogoutTimer();

    $("#entry-container").click(function() {
        timer.resetLogoutTimer();
    });

    window.onfocus = function () {
        timer.checkLogoutTimer();
    };
});
