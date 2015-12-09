function createAccount(e) {
    "use strict";
    e.preventDefault();

    var elem = $(e.target);
    var dataArray = elem.serializeArray();
    var url = elem.attr("action");
    var data = parseArray(dataArray);

    $.post(url, data, function (response) {
        console.log(response);
        window.location.href = "/done_signup/" + data.email;
        $("#error-msg-container").hide();
    }, "json").error(function(obj, textStatus, textCode) {
        if (textCode === "CONFLICT") {
            $("#error-msg").text("An account with this email already exists");
        } else if (textCode === "BAD REQUEST") {
            var response = JSON.parse(obj.responseText);
            console.log(response);
            $("#error-msg").text(response.msg);

            $(".form-error").text("");

            for (var k in response) {
                if (k !== "status" && k !== "msg") {
                    $("#form-error-" + k).text(response[k]);
                }
            }
        } else {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        }
        $("#error-msg-container").show();
    });

    return false;
}

function login(e) {
    "use strict";
    e.preventDefault();
    var elem = $(e.target);
    var dataArray = elem.serializeArray();
    var url = elem.attr("action");
    var data = parseArray(dataArray);
    console.log(data);
    postJSON(url, data)
    .done(function (response) {
        console.log(response);
        window.location.href = "/done_login";
        $("#error-msg-container").hide();
    }).error(function(obj, textStatus, textCode) {
        console.log(obj);
        if (textCode === "UNAUTHORIZED" || textCode === "BAD REQUEST") {
            var response = JSON.parse(obj.responseText);
            $("#error-msg").text(response.msg);
        } else {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        }
        $("#error-msg-container").show();
    });

    return false;
}
