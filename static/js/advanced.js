function doExport(e) {
    "use strict";
    e.preventDefault();

    var url = $("#export-form").attr("action");
    $.post(url, {}, function() {
        window.location.href = "/advanced/done_export";
    });

    return false;
}
