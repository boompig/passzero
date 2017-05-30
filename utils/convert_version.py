"""
This utility is used to convert all entries for a given user.

For now only works locally by hitting backend APIs
"""

# import json
import logging
from argparse import ArgumentParser
from getpass import getpass

# import requests

from passzero import backend
from passzero.my_env import DATABASE_URL
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BASE_URL = "https://localhost:5050"

def get_db_session():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()

# def get_entries_api(session):
    # r = session.get(BASE_URL + "/api/v1/entries")
    # assert r.status_code == 200
    # return json.loads(r.text)


# def save_entry_api(session, entry):
    # r = session.post(BASE_URL + "/api/v1/entries",
        # data = json.dumps(entry),
        # headers = { "Content-Type": "application/json" }
    # )
    # try:
        # assert r.status_code == 200
    # except AssertionError as e:
        # print r
        # print r.text
        # raise e
    # return r


# def login_api(session, email, master_key):
    # r = session.post(BASE_URL + "/api/v1/login",
        # data=json.dumps({ "email": email, "password": master_key }),
        # headers={ "Content-Type": "application/json" }
    # )
    # try:
        # assert r.status_code == 200
    # except AssertionError as e:
        # print r
        # print r.text
        # raise e

def update_entry(db_session, user, entry, dec_entry, password):
    new_entry = backend.encrypt_entry(password, dec_entry)
    new_entry.user_id = user.id
    # delete old entry
    db_session.delete(entry)
    # create new entry
    db_session.add(new_entry)
    return new_entry

def convert(email, password):
    db_session = get_db_session()
    user = backend.get_account_with_email(db_session, email)
    logging.info("Found user")
    entries = backend.get_entries(db_session, user.id)
    logging.info("Got entries")
    n = 0
    for entry in entries:
        if entry.version < 4:
            n += 1
            # convert to v<latest>
            logging.debug("found entry with version %d", entry.version)
            dec_entry = entry.decrypt(password)
            logging.debug("Successfully decrypted entry")
            new_entry = update_entry(
                    db_session, user, entry, dec_entry, password)
            # new_entry = backend.edit_entry(
                # db_session,
                # dec_entry["id"],
                # password,
                # dec_entry,
                # user.id
            # )
            assert new_entry.version >= 4
    logging.info("Saving %d changes...", n)
    # save in a single transaction
    db_session.commit()
    logging.info("Done")


def convert_live():
    pass
    # with requests.Session() as s:
        # login_api(s, email, password)
        # # get the entry, and then save it
        # entries = get_entries_api(s)
        # print(entries)
        # for entry in entries:
            # logging.debug("Found entry with ID %d" % entry["id"])
            # save_entry_api(s, entry)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger("requests").setLevel(logging.WARNING)
    parser = ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", default=None)
    args = parser.parse_args()
    password = (getpass() if args.password is None else args.password)
    convert(args.email, password)
