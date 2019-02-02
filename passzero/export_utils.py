import csv
from io import StringIO

from . import backend
from .models import User


EXPORT_FIELDS = [
    "website",
    "name",
    "login",
    "password",
    "note"
]


def export_decrypted_entries(db_session, user_id: int, master_password: str) -> str:
    assert isinstance(user_id, int)
    assert isinstance(master_password, str)
    user = db_session.query(User).filter_by(id=user_id).one()
    if not user.authenticate(master_password):
        raise Exception("Failed to authenticate user with given key")
    entries = backend.get_entries(db_session, user_id)
    # decrypt the entries
    dec_entries = [entry.decrypt(master_password) for entry in entries]
    service_map = backend.get_services_map(db_session)
    buf = StringIO()
    # this format is in the format expected by DashLane
    writer = csv.DictWriter(buf, fieldnames=[
        "website",
        "name",
        "login",
        "password",
        "note"
    ])
    writer.writeheader()
    for entry in dec_entries:
        website = None
        if entry["account"].lower() in service_map:
            website = service_map[entry["account"].lower()]["link"]
        writer.writerow({
            "website": website,
            "name": entry["account"],
            "login": entry["username"],
            "password": entry["password"],
            "note": entry["extra"]
        })
    out = buf.getvalue()
    return out
