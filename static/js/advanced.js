function doExport(e) {
    "use strict";
    e.preventDefault();

    var url = $("#export-form").attr("action");
    $.post(url, {}, function() {
        window.location.href = "/advanced/done_export";
    });

    return false;
}

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
            "use strict";
            $(".alert-success").text("Successfully changed password").show();
        },
        error: function (obj, textStatus, textCode) {
            "use strict";
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
