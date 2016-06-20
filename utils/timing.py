from __future__ import print_function
import time
from create_user import get_db_session
from passzero.backend import get_entries, get_account_with_email, decrypt_entries, create_inactive_user, activate_account, insert_entry_for_user
from passzero.models import Entry
import random


def get_user_id_by_email(db_session, email):
    user = get_account_with_email(db_session, email)
    return user.id


def create_active_user(db_session, email, password):
    """:return: user"""
    user = create_inactive_user(db_session, email, password)
    activate_account(db_session, user)
    return user


def create_fake_user(db_session):
    """:return: (user, plaintext password)"""
    email = "fake_fakington_%d@fake.com" % random.randint(1, 1000)
    password = "hello_world_%d" % random.randint(1, 1000)
    user = create_active_user(db_session, email, password)
    return (user, password)


def create_fake_entry_for_user(db_session, user_id, user_pt_password):
    n = random.randint(1, 1000000)
    dec_entry = {
        "account": "fake account %d" % n,
        "username": "fake email %d" % n,
        "password": "fake password %d" % n,
        "extra": ""
    }
    # create a long 'extra' string
    for i in range(1025):
        dec_entry["extra"] += "f"
    entry = insert_entry_for_user(db_session, dec_entry, user_id, user_pt_password)
    return entry


def time_decrypt_entries(db_session, user_id, user_pt_password):
    enc_entries = get_entries(db_session, user_id)
    print("Timing start")
    start = time.time()
    dec_entries = decrypt_entries(enc_entries, user_pt_password)
    end = time.time()
    print("Timing end")
    print("Time: %.2f seconds" % (end - start))


def delete_all_entries_for_user(db_session, user_id):
    entries = db_session.query(Entry).filter_by(user_id=user_id).all()
    for entry in entries:
        db_session.delete(entry)
    db_session.commit()


def delete_user(db_session, user):
    db_session.delete(user)
    db_session.commit()


def main():
    db_session = get_db_session()
    print("creating user...")
    user, user_pt_password = create_fake_user(db_session)
    try:
        for i in range(200):
            print("[%d] creating entry for user %d..." % (i + 1, user.id))
            entry = create_fake_entry_for_user(db_session, user.id, user_pt_password)
            print("Created entry with version %d" % entry.version)
        print("decrypting entries for user with ID %d..." % user.id)
        time_decrypt_entries(db_session, user.id, user_pt_password)
    except Exception as e:
        print(e)
        raise e
    finally:
        print("deleting all entries for user with ID %d..." % user.id)
        delete_all_entries_for_user(db_session, user.id)
        print("deleting user with ID %d..." % user.id)
        delete_user(db_session, user)


if __name__ == "__main__":
    #print("Running setup work")
    #db_session = get_db_session()
    #user_id = get_user_id_by_email(db_session, EMAIL)
    #print("Fetching entries")
    #enc_entries = get_entries(db_session, user_id)
    #print("Timing start")
    #start = time.time()
    #dec_entries = decrypt_entries(enc_entries, PASSWORD)
    #end = time.time()
    #print("Decrypting entries took %.2f seconds" % (end - start))
    main()
