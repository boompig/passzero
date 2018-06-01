"""
This utility is used to convert all entries for a given user.

For now only works locally by hitting backend APIs
"""
import sys
import os
try:
    assert os.getcwd().split("/")[-1] == "passzero"
except AssertionError:
    print("Error: expected to be run from passzero folder")
    sys.exit(1)
sys.path.append(os.getcwd())

import coloredlogs
import copy
import json
import logging
from argparse import ArgumentParser
from getpass import getpass
from typing import List

import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ["LIVE_TEST_HOST"] = "foo"
from tests.end_to_end_tests import api

from passzero import backend
from passzero.models import User, Entry
from passzero.my_env import DATABASE_URL

BASE_URL = "https://localhost:5050"


def get_db_session():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()


def update_entry(db_session, user: User, entry: Entry, dec_entry: dict, password: str) -> Entry:
    new_entry = backend.encrypt_entry(password, dec_entry)
    new_entry.user_id = user.id
    # delete old entry
    db_session.delete(entry)
    # create new entry
    db_session.add(new_entry)
    return new_entry


def convert(email: str, password: str, target_version: int = 4) -> None:
    logging.debug("Converting all entries to version %d", target_version)
    db_session = get_db_session()
    user = backend.get_account_with_email(db_session, email)
    logging.info("Found user withe email %s", email)
    entries = backend.get_entries(db_session, user.id)
    logging.info("Got %d entries", len(entries))
    n = 0
    for entry in entries:
        if entry.version != target_version:
            n += 1
            # convert to v<latest>
            logging.debug("found entry with version %d", entry.version)
            dec_entry = entry.decrypt(password)
            logging.debug("Successfully decrypted entry")
            new_entry = update_entry(
                    db_session, user, entry, dec_entry, password)
            assert new_entry.version >= 4
    if n == 0:
        logging.debug("No changes to be made")
    else:
        logging.info("Saving changes to %d entries...", n)
        # save in a single transaction
        db_session.commit()
    logging.info("Done")


def download_and_save_entries(s) -> List[dict]:
    # get the entry, and then save it
    entries = api.get_entries_v2(s).json()
    save_entries(entries)
    return entries


def save_entries(entries: List[dict]) -> None:
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

# class LiveConverter:
#     def __init__(self, base_url):
#         """
#         :param base_url:            The URL for the conversion - either localhost or live
#         """
#         self.base_url = base_url
#         self.api_token = None
#         self.api = api
#         self.api.BASE_URL = base_url

#     def convert_live_v5(self, email, password):
#         """Convert all the entries to entry version 5
#         """
#         pass


def convert_live_to_v5(email: str, password: str, base_url: str,
                       target_version: int = 5, dry_run: bool = False) -> None:
    client = api.ApiClient(base_url)
    key_fields = frozenset(["account", "username", "password", "extra", "has_2fa"])
    api_token = client.login(email, password)
    entries = client.get_encrypted_entries()
    save_entries(entries)
    for entry in entries:
        logging.debug("Found entry with ID %d", entry["id"])
        if entry["version"] != target_version:
            logging.info("Found an entry to convert: %d", entry["id"])
            # decrypt this entry
            dec_entry = client.decrypt_entry(entry["id"], password)
            new_entry = {}
            for field in dec_entry:
                if field in key_fields:
                    new_entry[field] = dec_entry[field]
            if dry_run:
                print(new_entry)
                print("Would normally create the new entry here...")
            else:
                #new_entry.pop("version")
                #new_entry.pop("id")
                new_entry_id = client.create_entry(new_entry, password)
                assert new_entry_id is not None
                # get the entry and compare all the relevant fields
                new_entry_dec = client.decrypt_entry(new_entry_id, password)
                for field in key_fields:
                    assert new_entry_dec[field] == dec_entry[field], "%s does not match" % field
                assert new_entry_dec["version"] == target_version, "new entry version must be %d" % target_version
                # now safe to delete the old entry
                client.delete_entry(entry["id"])
    print("Operation completed successfully")
    print("I recommend deleting the file with entries from /tmp/passzero")


def convert_live_to_v4(email: str, password: str, base_url: str, target_version: int = 4,
                       cleanup: bool = True):
    """Convert all the entries to the given version.
    :param base_url:            The URL for the conversion - either localhost or live

    TODO : cleanup param is not used ATM
    """
    api.BASE_URL = base_url
    with requests.Session() as s:
        api.login(s, email, password)
        entries = download_and_save_entries(s)
        for entry in entries:
            logging.debug("Found entry with ID %d" % entry["id"])
            if entry["version"] != target_version:
                logging.info("Found an entry to convert: %d" % entry["id"])
                csrf_token = api.get_csrf_token(s).json()
                new_entry = copy.deepcopy(entry)
                new_entry.pop("version")
                new_entry.pop("id")
                new_entry_id = api.create_entry(s, new_entry, csrf_token).json()
                assert new_entry_id is not None
                # get the entry and compare all the relevant fields
                new_entry_dec = api.get_entry_v2(s, new_entry_id).json()
                for field in ["account", "username", "password", "extra"]:
                    assert new_entry_dec[field] == entry[field], "%s does not match" % field
                assert new_entry_dec["version"] >= 4, "new entry version must be new"
                # now safe to delete the old entry
                delete_token = api.get_csrf_token(s).json()
                api.delete_entry(s, entry["id"], delete_token)
    print("Operation completed successfully")
    print("I recommend deleting the file with entries from /tmp/passzero")


def setup_logging(verbose: bool = False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")
    coloredlogs.install(level=log_level)
    logging.getLogger("requests").setLevel(logging.WARNING)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", default=None)
    parser.add_argument("--url", default=None,
        help="If URL is provided, hit that endpoint instead of using backend services")
    parser.add_argument("-v", "--verbose", action="store_true", default=False)
    parser.add_argument("--dry-run", action="store_true", default=False)
    args = parser.parse_args()
    setup_logging(args.verbose)
    password = (getpass() if args.password is None else args.password)
    if args.url:
        convert_live_to_v5(args.email, password, args.url, dry_run=args.dry_run)
    else:
        convert(args.email, password)
