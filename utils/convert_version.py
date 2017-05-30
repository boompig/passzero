"""
This utility is used to convert all entries for a given user.

For now only works locally by hitting backend APIs
"""

import copy
import json
import os
import logging
from argparse import ArgumentParser
from getpass import getpass

import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from passzero import backend
from passzero.my_env import DATABASE_URL
from . import api

BASE_URL = "https://localhost:5050"


def get_db_session():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()


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
            assert new_entry.version >= 4
    logging.info("Saving %d changes...", n)
    # save in a single transaction
    db_session.commit()
    logging.info("Done")


def download_and_save_entries(s):
    # get the entry, and then save it
    entries = api.get_entries_v2(s)
    if not os.path.exists("/tmp/passzero"):
        os.mkdir("/tmp/passzero")
    n = 1
    fname = "/tmp/passzero/entries-%d.json" % n
    while os.path.exists(fname):
        n += 1
        fname = "/tmp/passzero/entries-%d.json" % n
    with open(fname, "w") as fp:
        json.dump(entries, fp)
    print("Saved entries in file %s" % fname)
    return entries


def convert_live(email, password, base_url):
    api.BASE_URL = base_url
    with requests.Session() as s:
        api.login(s, email, password)
        entries = download_and_save_entries(s)
        for entry in entries:
            logging.debug("Found entry with ID %d" % entry["id"])
            if entry["version"] < 4:
                logging.info("Found an entry to convert: %d" % entry["id"])
                csrf_token = api.get_csrf_token(s)
                new_entry = copy.deepcopy(entry)
                new_entry.pop("version")
                new_entry.pop("id")
                new_entry_id = api.create_entry(s, new_entry, csrf_token)
                assert new_entry_id is not None
                # get the entry and compare all the relevant fields
                new_entry_dec = api.get_entry_v2(s, new_entry_id)
                for field in ["account", "username", "password", "extra"]:
                    assert new_entry_dec[field] == entry[field], "%s does not match" % field
                assert new_entry_dec["version"] >= 4, "new entry version must be new"
                # now safe to delete the old entry
                delete_token = api.get_csrf_token(s)
                api.delete_entry(s, entry["id"], delete_token)
    print("Operation completed successfully")
    print("I recommend deleting the file with entries from /tmp/passzero")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("requests").setLevel(logging.WARNING)
    parser = ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", default=None)
    parser.add_argument("--url", default=None,
        help="If URL is provided, hit that endpoint instead of using backend services")
    args = parser.parse_args()
    password = (getpass() if args.password is None else args.password)
    if args.url:
        convert_live(args.email, password, args.url)
    else:
        convert(args.email, password)
