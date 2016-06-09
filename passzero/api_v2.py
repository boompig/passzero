api_v2 = Blueprint("api_v2", __name__)


@api_v2.route("/api/v2/entries", methods=["POST"])
@api_v2.route("/api/entries/cse", methods=["POST"])
@requires_json_auth
@requires_csrf_check
def api_new_entry():
    request_data = request.get_json()
    form = NewEncryptedEntryForm(data=request_data)
    if form.validate():
        enc_entry = EncryptedEntry()
        enc_entry.account = request_data["account"]
        enc_entry.username = request_data["username"]
        enc_entry.password = request_data["password"]
        enc_entry.extra = request_data["extra"]
        enc_entry.key_salt = request_data["key_salt"]
        enc_entry.iv = request_data["iv"]
        enc_entry.user_id = session["user_id"]
        db.session.add(enc_entry)
        db.session.commit()
        result_data = { "entry_id": enc_entry.id }
        code = 200
    else:
        code, result_data = json_form_validation_error(form.errors)
    return write_json(code, result_data)


@api_v2.route("/api/v2/entries", methods=["GET"])
@requires_json_auth
def api_get_entries():
    entries = db.session.query(EncryptedEntry).filter_by(
            user_id=session['user_id']).all()
    l = [entry.to_json() for entry in entries]
    return write_json(200, l)


@api_v2.route("/api/v2/entries/<int:entry_id>", methods=["DELETE"])
@requires_json_auth
@requires_csrf_check
def api_delete_entry(entry_id):
    try:
        entry = db.session.query(EncryptedEntry).filter_by(id=entry_id).one()
        assert entry.user_id == session['user_id']
        db.session.delete(entry)
        db.session.commit()
        code, data = json_success("successfully deleted entry with ID %d" % entry_id)
    except NoResultFound:
        code, data = json_error(400, "no such entry")
    except AssertionError:
        code, data = json_error(400, "the given entry does not belong to you")
    return write_json(code, data)


