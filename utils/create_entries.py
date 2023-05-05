"""
This utility script is used for manual testing
"""
import logging
import os
import sys
from argparse import ArgumentParser

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from passzero.backend import get_account_with_email, insert_entry_for_user

load_dotenv()
DATABASE_URL = os.environ["DATABASE_URL"]


def get_db_session():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("-u", "--email", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-n", "--num-entries", type=int, default=120)
    parser.add_argument("-a", "--all-entry-versions", action="store_true",
                        help="By default only use latest entry versions. This creates entries of *all* versions")
    return parser.parse_args()


def setup_logging(verbose: bool = True) -> None:
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(level=log_level)


def create_fake_entry(i: int) -> dict:
    dec_entry = {
        "account": "fake account %d" % i,
        "username": "fake email %d" % i,
        "password": "fake password %d" % i,
        "extra": ("fake extra %d" % i if i % 2 == 0 else ""),
        "has_2fa": (i % 2 == 0)
    }
    return dec_entry


if __name__ == "__main__":
    args = parse_args()
    setup_logging(args.verbose)
    db_session = get_db_session()
    user = get_account_with_email(db_session, args.email)
    if not user.authenticate(args.password):
        logging.critical("Incorrect password for user %s", args.email)
        sys.exit(1)
    # evenly split between the different versions
    versions = [4, 5]
    if args.all_entry_versions:
        versions = [1, 2, 3, 4, 5]
    created_so_far = 0
    for j, version in enumerate(versions):
        num_entries_per_version = int(args.num_entries / len(versions))
        if j == len(versions) - 1:
            num_entries_per_version = args.num_entries - created_so_far
        logging.debug("Creating %d entries of version %d", num_entries_per_version, version)
        for i in range(num_entries_per_version):
            entry = create_fake_entry(i)
            insert_entry_for_user(db_session, entry, user.id, args.password, version=version,
                                  prevent_deprecated_versions=False)
            created_so_far += 1
    print("Created {} entries for user with email {}".format(num_entries_per_version * len(versions), args.email))
