function showHidePass(event) {
    var elem = $(event.target).parent().find(".password");
    console.log(elem);
    var t = elem.attr("type");
    if (t === "password") {
        elem.attr("type", "text");
        $(event.target).text("Hide");
    } else {
        elem.attr("type", "password");
        $(event.target).text("Show");
    }
}
