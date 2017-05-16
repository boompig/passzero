"""
This utility script is used for manual testing
"""
from argparse import ArgumentParser
from passzero.backend import get_account_with_email, insert_entry_for_user
from passzero.my_env import DATABASE_URL
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def get_db_session():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    return parser.parse_args()


def create_fake_entry(i):
    dec_entry = {
        "account": "fake account %d" % i,
        "username": "fake email %d" % i,
        "password": "fake password %d" % i,
        "extra": ""
    }
    return dec_entry


if __name__ == "__main__":
    num_entries_per_version = 40
    args = parse_args()
    db_session = get_db_session()
    user = get_account_with_email(db_session, args.email)
    if not user.authenticate(args.password):
        print("Incorrect password for user")
    # evenly split between the different versions: 2, 3, 4
    versions = [2, 3, 4]
    for version in versions:
        for i in range(num_entries_per_version):
            entry = create_fake_entry(i)
            insert_entry_for_user(db_session, entry, user.id, args.password, version=version)
    print("Created %d entries for user with email %s" % (num_entries_per_version * len(versions), args.email))
