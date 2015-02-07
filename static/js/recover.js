function recoverPassword(e) {
    "use strict";
    e.preventDefault();
    var url = $(e.target).prop("action");
    var data = {
        email: $("input[type='email']").val()
    };
    $.post(url, data, function(response, textStatus, obj) {
        "use strict";
        $("#success-msg").addClass("alert-success").text(response.msg).show();
        console.log(response);
    }, "json");
    return false;
}

function recoverPasswordConfirm(e) {
    "use strict";
    e.preventDefault();
    var url = $(e.target).prop("action");
    var data = {
        password: $("input[name='password']").val(),
        confirm_password: $("input[name='confirm_password']").val(),
        token: window.location.search.replace("?token=", "")
    };
    $.post(url, data, function(response, textStatus, obj) {
        "use strict";
        console.log(response);
        window.location.href = "/logout"
    }, "json").error(function(obj, b) {
        "use strict";
        $("#server-msg").text(obj.responseJSON.msg);
        console.log("error");
        console.log(obj.responseJSON);
    });
    return false;
}

$(function () {
    "use strict";

    $("#accept-risk").click(function() {
        var c = $("#accept-risk").prop("checked");
        console.log("checked = %s", c);
        $("button[type='submit']").prop("disabled", !c);
    });
});
