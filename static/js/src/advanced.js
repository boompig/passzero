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
