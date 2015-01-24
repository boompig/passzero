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
    }, "json").error(function(obj, textStatus, textCode) {
        if (textCode === "CONFLICT") {
            $(".error").text("An account with this email already exists");
        } else {
            console.log(textStatus);
            console.log(textCode);
        }
    });

    return false;
}
