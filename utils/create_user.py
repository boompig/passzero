"""
This utility script is used for manual testing
"""
import getpass
from argparse import ArgumentParser

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from passzero.backend import activate_account, create_inactive_user
from passzero.my_env import DATABASE_URL


def get_db_session() -> Session:
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password",
                        help="Optionally specify on the command-line. Otherwise ask securely.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    db_session = get_db_session()
    if args.password:
        password = args.password
    else:
        password = getpass.getpass()
    user = create_inactive_user(db_session, args.email, password)
    activate_account(db_session, user)
    print("User with email %s created" % args.email)
