"""
This file tests different versions of encrypt/decrypt algorithms for performance

This file also tests the performance of the web server at servicing typical requests
"""

import cProfile
import logging
import os
import pstats
import random
import time
from argparse import ArgumentParser
from pprint import pprint
from typing import Optional, List, Tuple

import requests
from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from create_user import get_db_session
from passzero import backend
from passzero.api.entry_list import jsonify_entries
from passzero.models import Entry, User
from utils import api

# number of entries to create for a user
NUM_ENTRIES = 300
DEFAULT_EMAIL = "testing@example.com"
DEFAULT_PASSWORD = "hello_world_test"


def read_words() -> List[str]:
    with open("static/dictionary/words.txt") as fp:
        words = [line.rstrip() for line in fp]
    return words


WORDS = read_words()


def get_user_by_email(db_session: Session, email: str) -> User:
    user = backend.get_account_with_email(db_session, email)
    return user


def create_active_user(db_session: Session, email: str, password: str):
    """:return: user"""
    user = backend.create_inactive_user(db_session, email, password)
    backend.activate_account(db_session, user)
    return user


def create_fake_user(db_session: Session, email: Optional[str] = None,
                     password: Optional[str] = None) -> Tuple[User, str]:
    """:return: (user, plaintext password)"""
    if email is None:
        email = "fake_fakington_%d@fake.com" % random.randint(1, 1000)
    if password is None:
        password = "hello_world_%d" % random.randint(1, 1000)
    user = create_active_user(db_session, email, password)
    return (user, password)


def get_fake_account_name(random_nonce: str):
    base = " ".join(random.sample(WORDS, 2))
    return base + " " + random_nonce


def create_fake_entry_for_user(db_session: Session, user_id, user_pt_password, version=4):
    random_nonce = str(hash(random.random()))
    account_name = get_fake_account_name(random_nonce)

    dec_entry = {
        "account": account_name,
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


def _decrypt_entries_normal_v2(db_session: Session, user_id: int, master_key: str):
    entries = backend.get_entries(db_session, user_id)
    l = []
    for entry in entries:
        if entry.version == 4:
            l.append(entry.to_json())
        else:
            l.append(entry.decrypt(master_key))
    return l


def decrypt_entries_v2(enc_entries, master_key: str):
    return _decrypt_entries_multiprocess_v2(enc_entries, master_key)


def time_decrypt_entries_v2(db_session: Session, user_id: int, user_pt_password: str):
    enc_entries = backend.get_entries(db_session, user_id)
    print("[v2] Timing start: v2")
    start = time.time()
    dec_entries = decrypt_entries_v2(enc_entries, user_pt_password)
    end = time.time()
    print("[v2] Timing end")
    print("[v2] Time: %.2f seconds" % (end - start))
    return dec_entries


def time_decrypt_entries_v1(db_session: Session, user_id: int, user_pt_password: str):
    enc_entries = backend.get_entries(db_session, user_id)
    print("[v1] Timing start")
    start = time.time()
    dec_entries = backend.decrypt_entries(enc_entries, user_pt_password)
    end = time.time()
    print("[v1] Timing end")
    print("[v1] Time: %.2f seconds" % (end - start))
    return dec_entries


def time_decrypt_entries(db_session: Session, user_id: int, user_pt_password: str):
    enc_entries = backend.get_entries(db_session, user_id)
    print("Timing start")
    start = time.time()
    dec_entries = backend.decrypt_entries(enc_entries, user_pt_password)
    end = time.time()
    print("Timing end")
    print("Time: %.2f seconds" % (end - start))
    return dec_entries


def time_decrypt_partial(db_session: Session, user_id: int, user_pt_password: str):
    enc_entries = backend.get_entries(db_session, user_id)
    print("Timing start")
    start = time.time()
    partially_dec_entries = [{"account": entry.account} for entry in enc_entries]
    end = time.time()
    print("Timing end")
    print("Time: %.2f seconds" % (end - start))
    return partially_dec_entries


def delete_all_entries_for_user(db_session: Session, user_id: int):
    """Delete the entries individually"""
    entries = db_session.query(Entry).filter(and_(
        Entry.user_id == user_id,
        Entry.pinned == False  # noqa
    )).all()
    for entry in entries:
        db_session.delete(entry)
    db_session.commit()


def main(version: int):
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
        backend.delete_all_entries(db_session, user, user_pt_password)
        logging.debug("deleting user with ID %d...", user.id)
        backend.delete_account(db_session, user)


def main_api_v2(proportions: dict):
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
        backend.delete_all_entries(db_session, user.id, user_pt_password)
        logging.info("deleting user with ID %d...", user.id)
        backend.delete_account(db_session, user)


def create_fake_entries_for_user(db_session: Session,
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
        backend.delete_account(db_session, user)

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
                backend.delete_all_entries(db_session, user, user_pt_password)
    except Exception as e:
        logging.error(e)
        raise e
    finally:
        logging.info("deleting user with ID %d...", user.id)
        backend.delete_account(db_session, user)


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


def time_jsonify_encrypted_entries(num_entries_list: List[int], cleanup: bool = True):
    """
    It is November 16, 2021 and the current problem I'm debugging is that it's over half a second to get the encrypted entries on the local server.
    On Heroku, it's taking as much as 1.5 seconds and usually around 800ms.
    After I added logging, it looks like the encoding process of around 500 entries is the element that's taking so long.
    To test this theory, let's create a bunch of entries and see how long it takes to encode them.

    Based on the profiling below, for some reason the Entry objects' properties are expired

    Here are the current times (using our to_json method):

    GET:
    - 300: 0.01s, 0.01s, 0.01s
    - 400: 0.02s, 0.02s, 0.02s
    - 500: 0.02s, 0.02s, 0.02s
    - 600: 0.02s, 0.02s, 0.02s

    JSONIFY:
    - 300: 0.20s, 0.21s, 0.21s
    - 400: 0.26s, 0.26s, 0.27s
    - 500: 0.32s, 0.34s, 0.42s
    - 600: 0.44s, 0.40s, 0.40s

    And using the old method:

    GET:
    - 300: 0.01s, 0.01s
    - 400: 0.02s, 0.02s
    - 500: 0.02s, 0.02s
    - 600: 0.02s, 0.03s

    JSONIFY:
    - 300: 0.20s, 0.23s
    - 400: 0.30s, 0.29s
    - 500: 0.36s, 0.33s
    - 600: 0.41s, 0.42s

    It's about the same.

    I then enabled postgres statement-level logging. It turns out that some properties were not being loaded at the initial select statement level.
    They were only loaded once we accessed the entry, because that property was set on Entry v5 only.
    By moving the property up to the base entry, I was able to fix it.

    :param cleanup: By default we delete the entry and user at the end of the testcase
    """

    db_session = get_db_session()
    pid = os.getpid()
    try:
        user, user_pt_password = create_fake_user(db_session, email=DEFAULT_EMAIL, password=DEFAULT_PASSWORD)
    except IntegrityError:
        logging.warning("User with email %s already exists. Using that one.", DEFAULT_EMAIL)
        db_session.rollback()
        user = get_user_by_email(db_session, email=DEFAULT_EMAIL)
        user_pt_password = DEFAULT_PASSWORD

    # cleanup just in case
    if cleanup:
        backend.delete_all_entries(db_session, user, user_pt_password)
        num_current_entries = 0
    else:
        enc_entries = backend.get_entries(db_session, user.id)
        num_current_entries = len(enc_entries)
        logging.warning("Starting test case with %d entries. Not cleaning these up.", num_current_entries)

    db_session.flush()

    try:
        for num_entries in num_entries_list:
            print(f"[run {pid}] Running test on {num_entries} entries")

            print(f"[run {pid}] Creating entries...")
            # reuse the entries between different parts of timing
            while num_current_entries < num_entries:
                enc_entry = create_fake_entry_for_user(db_session, user.id, user_pt_password, version=5)
                assert enc_entry.version == 5
                num_current_entries += 1
            print(f"[run {pid}] Created {num_entries} entries")

            db_session.flush()
            # reset the session
            db_session.close()

            user = get_user_by_email(db_session, email=DEFAULT_EMAIL)

            profiler = cProfile.Profile()
            profiler.enable()
            start = time.time()
            enc_entries = backend.get_entries(db_session, user.id)
            for entry in enc_entries:
                assert entry.version == 5
            end = time.time()
            profiler.disable()
            print(f"[run {pid}] get_entries : # entries = {num_entries}, time = {end-start:.2f} seconds")
            stats = pstats.Stats(profiler).sort_stats('cumtime')
            fname = f"data/stats-{num_entries}-get-entries-{pid}.profile"
            stats.dump_stats(fname)
            print(f"[run {pid}] Dumped get_entries stats to file {fname}")

            profiler = cProfile.Profile()
            profiler.enable()
            start = time.time()
            jsonify_entries(enc_entries)
            end = time.time()
            profiler.disable()
            print(f"[run {pid}] jsonify_entries : # entries = {num_entries}, time = {end-start:.2f} seconds")
            stats = pstats.Stats(profiler).sort_stats('cumtime')
            fname = f"data/stats-{num_entries}-jsonify-entries-{pid}.profile"
            stats.dump_stats(fname)
            print(f"[run {pid}] Dumped jsonify_entries stats to file {fname}")
            print("")

    except Exception as err:
        logging.exception(err)
    finally:
        if cleanup:
            # entries are deleted when account is deleted
            user = get_user_by_email(db_session, email=DEFAULT_EMAIL)
            backend.delete_account(db_session, user)
        else:
            logging.warning("Not cleaning up")


def read_pstats(fname):
    p = pstats.Stats(fname)
    p.strip_dirs()
    p.sort_stats('cumtime')
    p.print_stats(50)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.WARNING)

    parser = ArgumentParser()
    parser.add_argument("--create-live", action="store_true", default=False,
                        help="Use to test the speed with server")
    parser.add_argument("--version", type=int,
                        help="For use with --live")
    parser.add_argument("--delete-live", action="store_true", default=False,
                        help="Cleanup of --create-live")
    parser.add_argument("--time-jsonify-entries", action="store_true", default=False,
                        help="Time how long it takes to JSON-ify varying numbers of encrypted entries")
    parser.add_argument("--get-live", action="store_true", default=False,
                        help="After creating the entries (not over web server), evaluate performance of getting all encrypted entries")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Use with --time-jsonify-entries. Do not clean up created user and entries.")
    parser.add_argument("--read-pstats", type=str,
                        help="pstats file to read")

    args = parser.parse_args()

    random.seed(42)

    if args.create_live:
        assert args.version is not None, "--version must be set with --live"
        test_live(args.version)
    elif args.delete_live:
        delete_live()
    elif args.get_live:
        get_live()
    elif args.time_jsonify_entries:
        time_jsonify_encrypted_entries(
            num_entries_list=[10, 100],
            cleanup=not args.no_cleanup
        )
    elif args.read_pstats:
        read_pstats(args.read_pstats)
    else:
        main_api_v2({4: 0, 3: 100})
        main_api_v2({4: 20, 3: 80})
        main_api_v2({4: 50, 3: 50})
        main_api_v2({4: 80, 3: 20})
