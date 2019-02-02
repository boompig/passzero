"""
This file tests different versions of encrypt/decrypt algorithms for performance

This file also tests the performance of the web server at servicing typical requests
"""

from __future__ import print_function

import logging
import os
import random
import time
from argparse import ArgumentParser
from pprint import pprint

import requests

from create_user import get_db_session
from passzero import backend
from passzero.models import ApiToken, Entry, User
from utils import api

# number of entries to create for a user
NUM_ENTRIES = 300


def get_user_id_by_email(db_session, email):
    user = backend.get_account_with_email(db_session, email)
    return user.id


def create_active_user(db_session, email: str, password: str):
    """:return: user"""
    user = backend.create_inactive_user(db_session, email, password)
    backend.activate_account(db_session, user)
    return user


def create_fake_user(db_session):
    """:return: (user, plaintext password)"""
    email = "fake_fakington_%d@fake.com" % random.randint(1, 1000)
    password = "hello_world_%d" % random.randint(1, 1000)
    user = create_active_user(db_session, email, password)
    return (user, password)


def get_fake_account_name(random_nonce: str):
    with open("static/dictionary/words.txt") as fp:
        words = [line.rstrip() for line in fp]
    base = " ".join(random.sample(words, 2))
    return base + " " + random_nonce


def create_fake_entry_for_user(db_session, user_id, user_pt_password, version=4):
    # account name will be generated from the static words
    random_nonce = str(hash(random.random()))
    dec_entry = {
        "account": get_fake_account_name(random_nonce),
        "username": "fake email %s" % random_nonce,
        "password": "fake password %s" % random_nonce,
        "extra": "a very long extra string %s" % random_nonce,
        "has_2fa": random.random() < 0.5
    }
    # create a long 'extra' string
    # but break it up with some line breaks
    for i in range(1025):
        if random.random() < 0.1:
            dec_entry["extra"] += "\n"
        dec_entry["extra"] += "f"
    entry = backend.insert_entry_for_user(
        db_session,
        dec_entry,
        user_id,
        user_pt_password,
        version=version
    )
    return entry

def _decrypt_entry_v2(pair):
    entry, master_key = pair
    if entry.version >= 4:
        return entry.to_json()
    else:
        return entry.decrypt(master_key)

def _decrypt_entries_multiprocess_v2(entries, master_key):
    from multiprocessing import Pool
    pool = Pool(5)
    entry_key_pairs = [(entry, master_key) for entry in entries]
    results = pool.map(_decrypt_entry_v2, entry_key_pairs)
    pool.close()
    pool.join()
    return results

def _decrypt_entries_normal_v2(db_session, user_id, master_key):
    entries = backend.get_entries(db_session, user_id)
    l = []
    for entry in entries:
        if entry.version == 4:
            l.append(entry.to_json())
        else:
            l.append(entry.decrypt(master_key))
    return l

def decrypt_entries_v2(enc_entries, master_key):
    return _decrypt_entries_multiprocess_v2(enc_entries, master_key)


def time_decrypt_entries_v2(db_session, user_id, user_pt_password):
    enc_entries = backend.get_entries(db_session, user_id)
    print("[v2] Timing start: v2")
    start = time.time()
    dec_entries = decrypt_entries_v2(enc_entries, user_pt_password)
    end = time.time()
    print("[v2] Timing end")
    print("[v2] Time: %.2f seconds" % (end - start))
    return dec_entries

def time_decrypt_entries_v1(db_session, user_id, user_pt_password):
    enc_entries = backend.get_entries(db_session, user_id)
    print("[v1] Timing start")
    start = time.time()
    dec_entries = backend.decrypt_entries(enc_entries, user_pt_password)
    end = time.time()
    print("[v1] Timing end")
    print("[v1] Time: %.2f seconds" % (end - start))
    return dec_entries


def time_decrypt_entries(db_session, user_id, user_pt_password):
    enc_entries = backend.get_entries(db_session, user_id)
    print("Timing start")
    start = time.time()
    dec_entries = backend.decrypt_entries(enc_entries, user_pt_password)
    end = time.time()
    print("Timing end")
    print("Time: %.2f seconds" % (end - start))
    return dec_entries


def time_decrypt_partial(db_session, user_id, user_pt_password):
    enc_entries = backend.get_entries(db_session, user_id)
    print("Timing start")
    start = time.time()
    partially_dec_entries = [
            {"account": entry.account} for entry in enc_entries ]
    end = time.time()
    print("Timing end")
    print("Time: %.2f seconds" % (end - start))
    return partially_dec_entries


def delete_all_entries_for_user(db_session, user_id):
    entries = db_session.query(Entry).filter_by(user_id=user_id).all()
    for entry in entries:
        db_session.delete(entry)
    db_session.commit()


def delete_user(db_session, user):
    db_session.query(ApiToken).delete()
    db_session.delete(user)
    db_session.commit()


def main(version):
    print("Testing entries with version {}".format(version))
    db_session = get_db_session()
    logging.debug("creating user...")
    user, user_pt_password = create_fake_user(db_session)
    try:
        logging.info("Creating %d entries for user %d...", NUM_ENTRIES, user.id)
        for i in range(NUM_ENTRIES):
            logging.debug("[%d] creating entry for user %d...", i + 1, user.id)
            entry = create_fake_entry_for_user(
                db_session, user.id, user_pt_password, version=version)
            assert entry.version == version
            logging.debug("Created entry with version %d", entry.version)
        logging.info("Created %d entries for user %d", NUM_ENTRIES, user.id)
        logging.info("decrypting entries for user with ID %d...", user.id)
        if version == 4:
            entries = time_decrypt_partial(db_session, user.id, user_pt_password)
        else:
            entries = time_decrypt_entries(db_session, user.id, user_pt_password)
        assert len(entries) == NUM_ENTRIES, \
            "Number of decrypted entries should be number inserted"
    except Exception as e:
        logging.error(e)
        raise e
    finally:
        logging.debug("deleting all entries for user with ID %d...", user.id)
        delete_all_entries_for_user(db_session, user.id)
        logging.debug("deleting user with ID %d...", user.id)
        delete_user(db_session, user)

def main_api_v2(proportions):
    print("Testing entries with version proportions {}".format(str(proportions)))
    db_session = get_db_session()
    logging.debug("creating user...")
    user, user_pt_password = create_fake_user(db_session)
    try:
        n = 0
        for version, num_entries in proportions.items():
            logging.info("Creating %d entries for version %d...", num_entries, version)
            for i in range(num_entries):
                n += 1
                logging.debug("[%d] creating entry for user %d...", i + 1, user.id)
                entry = create_fake_entry_for_user(
                    db_session, user.id, user_pt_password, version=version)
                assert entry.version == version
                logging.debug("Created entry with version %d", entry.version)
        logging.info("Created %d entries for user %d", n, user.id)
        logging.info("decrypting entries for user with ID %d...", user.id)
        entries = time_decrypt_entries_v2(db_session, user.id, user_pt_password)
        assert len(entries) == n, \
            "Number of decrypted entries should be number inserted (v2)"
        entries = time_decrypt_entries_v1(db_session, user.id, user_pt_password)
        assert len(entries) == n, \
            "Number of decrypted entries should be number inserted (v1)"
    except Exception as e:
        logging.error(e)
        raise e
    finally:
        logging.info("deleting all entries for user with ID %d...", user.id)
        delete_all_entries_for_user(db_session, user.id)
        logging.info("deleting user with ID %d...", user.id)
        delete_user(db_session, user)


def create_fake_entries_for_user(db_session,
        user_id: int,
        password: str,
        version: int,
        num: int) -> None:
    for i in range(num):
        logging.debug("[%d] creating entry for user %d...", i + 1, user_id)
        entry = create_fake_entry_for_user(
            db_session, user_id, password, version=version)
        assert entry.version == version
        logging.debug("Created entry with version %d", entry.version)


def save_user_id(user_id):
    if not os.path.exists("/tmp/passzero"):
        os.mkdir("/tmp/passzero")
    fname = "/tmp/passzero/timing-userid.txt"
    with open(fname, "w") as fp:
        fp.write("%d\n" % user_id)
    logging.info("Wrote user ID to file %s" % fname)


def test_live(version):
    """
    Create entries and then check the difference in real time.
    i.e. fire up the server and actually see how long everything takes to load
    """
    db_session = get_db_session()
    logging.debug("creating user...")
    user, user_pt_password = create_fake_user(db_session)
    logging.info("Creating %d entries. email = %s password = %s",
        NUM_ENTRIES, user.email, user_pt_password)
    try:
        create_fake_entries_for_user(db_session, user.id, user_pt_password,
            version=version, num=NUM_ENTRIES)
    except Exception as e:
        logging.error(e)
        raise e
        # delete the user
        delete_user(db_session, user)
        
    save_user_id(user.id)


def get_live(
        base_url: str = "https://localhost:5050",
        num_samples: int = 5) -> None:
    """
    Test how fast we perform with a token
    """
    logging.info("Testing webserver speed to fetch entries")
    api.BASE_URL = base_url
    db_session = get_db_session()
    logging.debug("creating user...")
    user, user_pt_password = create_fake_user(db_session)
    try:
        for num_entries in [50, 100, 200, 300, 400, 500]:
            try:
                logging.debug("Creating %d entries...", num_entries)
                create_fake_entries_for_user(
                    db_session, user.id, user_pt_password,
                    version=4,
                    num=num_entries
                )
                logging.debug("Created %d entries for user %d", num_entries, user.id)
                # do this live
                logging.info("Starting test with %d entries...", num_entries)
                with requests.Session() as s:
                    token = api.login_with_token(s, user.email, user_pt_password, check_status=True)
                    times = []
                    for i in range(num_samples):
                        start = time.time()
                        entries = api.get_encrypted_entries_with_token(s, token, check_status=True)
                        if len(entries) != num_entries:
                            pprint(entries)
                        assert len(entries) == num_entries, "Expected %d entries, got %d" % (num_entries, len(entries))
                        end = time.time()
                        logging.debug("[%d] Time to get %d entries: %.2f seconds" % (i + 1, num_entries, end - start))
                        times.append(end - start)
                    avg_time_ms = sum([time * 1000 for time in times]) / len(times)
                    print("Average time to get %d entries: %.d ms across %d samples" % (
                        num_entries, avg_time_ms, num_samples))
            finally:
                logging.info("deleting all entries for user with ID %d...", user.id)
                delete_all_entries_for_user(db_session, user.id)
    except Exception as e:
        logging.error(e)
        raise e
    finally:
        logging.info("deleting user with ID %d...", user.id)
        delete_user(db_session, user)

    


def delete_live():
    fname = "/tmp/passzero/timing-userid.txt"
    assert os.path.exists(fname), "File with user ID must exist"
    with open(fname, "r") as fp:
        user_id = int(fp.read().strip())
    db_session = get_db_session()
    logging.info("deleting all entries for user with ID %d...", user_id)
    delete_all_entries_for_user(db_session, user_id)
    logging.info("deleting user with ID %d...", user_id)
    try:
        db_session.query(User).filter_by(id=user_id).one()
        db_session.query(User).filter_by(id=user_id).delete()
        db_session.commit()
    except Exception as e:
        print(type(e))
        print(e)
        pass
    # remove the filename containing the relevant user ID
    os.remove(fname)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s")
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.WARNING)

    parser = ArgumentParser()
    parser.add_argument("--create-live", action="store_true", default=False,
        help="Use to test the speed with server")
    parser.add_argument("--version", type=int,
        help="For use with --live")
    parser.add_argument("--delete-live", action="store_true", default=False,
        help="Cleanup of --create-live")
    parser.add_argument("--get-live", action="store_true", default=False,
        help="After creating the entries (not over web server), evaluate performance of getting all encrypted entries")

    args = parser.parse_args()

    random.seed(42)

    if args.create_live:
        assert args.version is not None, "--version must be set with --live"
        test_live(args.version)
    elif args.delete_live:
        delete_live()
    elif args.get_live:
        get_live()
    else:
        main_api_v2({4: 0, 3: 100})
        main_api_v2({4: 20, 3: 80})
        main_api_v2({4: 50, 3: 50})
        main_api_v2({4: 80, 3: 20})
