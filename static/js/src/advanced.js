function changePassword(e) {
    "use strict";
    e.preventDefault();

    var elem = $(e.target);
    var url = elem.attr("action");
    var dataArray = elem.serializeArray();
    var data = parseArray(dataArray);

    $(".form-error").text("");
    $(".error-msg").text("");
    $(".alert-success").hide();

    $.ajax({
        url: url,
        data: data,
        success: function (response) {
            $(".alert-success").text("Successfully changed password").show();
            // reset form fields
            elem.find("input[type='password']").each(function (idx) {
                $(this).val("");
            });
        },
        error: function (obj, textStatus, textCode) {
            var response = obj.responseJSON;
            $(".error-msg").text(response.msg);

            for (var key in response) {
                if (key !== "status" && key !== "msg") {
                    $("#form-error-" + key).text(response[key]);
                }
            }
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        },
        method: "UPDATE"
    });

    return false;
}

function nukeEntries(e) {
    "use strict";
    e.preventDefault();
    if (confirm("Are you sure you want to delete all your entries?")) {
        var $elem = $(e.target);
        var url = $elem.attr("action");
        var csrf_token = $elem.find("[name='csrf_token']").val();
        var data = { "csrf_token": csrf_token };
        $.post(url, data, function(response) {
            $("#nuke-success-msg").text(response.msg).show();
        }, "json");
    }
    return false;
}
