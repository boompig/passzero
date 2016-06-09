from argparse import ArgumentParser
from passzero.backend import create_inactive_user, activate_account
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


if __name__ == "__main__":
    args = parse_args()
    db_session = get_db_session()
    user = create_inactive_user(db_session, args.email, args.password)
    activate_account(db_session, user)
    print("User with email %s created" % args.email)
