"""
Perform the inverse of the export API
Import from the CSV file generated by the export API
"""

import getpass
import logging
import os
from argparse import ArgumentParser, FileType
from csv import DictReader

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from passzero.backend import (delete_all_entries, get_account_with_email,
                              insert_new_entry)
from passzero.models import Entry

load_dotenv()
DATABASE_URL = os.environ["DATABASE_URL"]


def get_db_session():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()


def import_entries(email: str, password: str, entries):
    logging.info("Saving entries...")
    db_session = get_db_session()
    user = get_account_with_email(db_session, args.email)
    for entry in entries:
        # create entry
        e = Entry()
        e.account = entry["account"]
        e.username = entry["username"]
        e.password = entry["password"]
        e.padding = entry["padding"]
        e.extra = entry["extra"]
        e.key_salt = entry["key_salt"]
        e.iv = entry["iv"]
        e.version = entry["version"]
        e.pinned = entry["pinned"]
        insert_new_entry(db_session, e, user.id)
    db_session.commit()
    logging.info("Saving entries complete.")


def read_entries_from_file(fp):
    logging.info("Reading entries from file %s", repr(fp))
    entries = []
    reader = DictReader(fp)
    for row in reader:
        entries.append(row)
    logging.info("Read %d entries from file", len(entries))
    return entries


def delete_entries(email: str, password: str):
    db_session = get_db_session()
    user = get_account_with_email(db_session, email)
    delete_all_entries(db_session, user, password)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = ArgumentParser()
    parser.add_argument("--email", required=True,
                        help="Email for existing account")
    parser.add_argument("--password",
                        help="Password for existing account. Can supply here otherwise ask securely.")
    parser.add_argument("--csv", type=FileType("r"), required=True,
                        help="Path to the CSV file")
    args = parser.parse_args()
    entries = read_entries_from_file(args.csv)
    if args.password:
        password = args.password
    else:
        password = getpass.getpass()
    try:
        import_entries(args.email, password, entries)
    except Exception as e:
        delete_entries(args.email, password)
        raise e
