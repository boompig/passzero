"""
NOTE: This script creates some potentially sensitive files in the directory `data`
It does try to secure them a little but I would recommend deleting the entire directory when you're done with the script
"""

import logging
from argparse import ArgumentParser
import hashlib
import requests
from tests.common import api
import getpass
import json
import os
from typing import Set, List, Dict, Iterable
from pprint import pprint
import time


LIVE_URL = "https://passzero.herokuapp.com"
USERNAME_FILE = "data/usernames.json"
PASSWORD_HASH_FILE = "data/password_hashes.json"


def setup_logging(verbose: bool):
	log_level = (logging.DEBUG if verbose else logging.INFO)
	logging.basicConfig(
		level=log_level,
		format="[%(levelname)s] %(message)s"
	)
	logging.getLogger("urllib3").setLevel(logging.WARNING)
	try:
		import coloredlogs
		coloredlogs.install(level=log_level)
	except ImportError:
		logging.debug("Failed to import coloredlogs")


def save_usernames(usernames: Set[str]) -> str:
	make_private_data_dir()
	fname = USERNAME_FILE
	with open(fname, "w") as fp:
		json.dump({
			"usernames": list(usernames)
		}, fp, indent=4)
	return fname


def read_usernames(fname: str) -> List[str]:
	with open(fname) as fp:
		content = json.load(fp)
		return content["usernames"]


def is_email(username: str) -> bool:
	return "@" in username and " " not in username
	#and "+" not in username


def download_entries(username: str, password: str) -> Dict[int, dict]:
	"""Download and decrypt all entries from PZ"""
	session = requests.Session()
	apiv3 = api.ApiV3(session, LIVE_URL)
	logging.debug("Logging in with %s", username)
	try:
		apiv3.login(username, password)
	except api.BadStatusCodeException:
		logging.critical("Failed to login")
		exit(1)
	logging.debug("Successfully logged in")
	entries = apiv3.get_encrypted_entries()
	num_entries = len(entries)
	logging.info("Got %d encrypted entries", num_entries)
	logging.info("Decrypting entries...")
	dec_entries = {}
	for i, entry in enumerate(entries):
		entry_id = entry["id"]
		logging.debug("Decrypting entry %d - %d / %d", entry_id, i + 1, num_entries)
		dec_entries[entry_id] = apiv3.decrypt_entry(entry_id)
	logging.info("Decrypted all entries")
	return dec_entries


def download_usernames(username: str, password: str):
	"""Download usernames for all entries in PassZero and save in JSON file"""
	dec_entries = download_entries(username, password)
	usernames = set([])
	for entry_id, dec_entry in dec_entries.items():
		usernames.add(dec_entry["username"])
	username_fname = save_usernames(usernames)
	logging.info("Saved usernames in %s", username_fname)


def download_sha1_password_hashes(username: str, master_password: str) -> Dict:
	dec_entries = download_entries(username, master_password)
	hashed_passwords = {}
	for entry_id, dec_entry in dec_entries.items():
		# do not include entries with empty passwords
		if dec_entry["password"] == "" or dec_entry["password"] == "-":
			logging.debug("Ignoring entry with empty password: %s", dec_entry["account"])
			continue
		h = hashlib.sha1()
		h.update(dec_entry["password"].encode('utf-8'))
		hashed_passwords[dec_entry["account"]] = {
			"sha1": h.hexdigest(),
			# this is useful to ignore PINs
			"is_numeric": dec_entry["password"].isdigit()
		}
	save_hashes(hashed_passwords)
	logging.info("Saved password hashes in %s", PASSWORD_HASH_FILE)
	return hashed_passwords


def make_private_data_dir():
	try:
		os.mkdir("data", mode=0o700)
	except IOError:
		logging.debug("data directory already exists")


def save_hashes(hashes: Dict[str, dict]) -> str:
	make_private_data_dir()
	fname = PASSWORD_HASH_FILE
	with open(fname, "w") as fp:
		json.dump(hashes, fp, indent=4)
	return fname


class EmailNotFoundError(Exception):
	pass


def get_breaches_per_email(email: str) -> dict:
	headers = {
		"User-Agent": "passzero-password-manager"
	}
	r = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers)
	if r.ok:
		breaches = r.json()
		# print(breaches)
		return breaches
	elif r.status_code == 404:
		raise EmailNotFoundError(email)
	else:
		print(r.status_code)
		logging.critical("Failed to get breach for %s", email)
		print(r.text)
		exit(1)


def save_breaches(fname: str, all_breaches: Dict[str, dict]) -> None:
	with open(fname, "w") as fp:
		json.dump(all_breaches, fp, indent=4)


def get_breaches_for_emails(emails: Iterable[str], save: bool = True) -> None:
	all_breaches = {}
	breaches_fname = "data/breaches.json"
	for email in emails:
		try:
			breaches = get_breaches_per_email(email)
			# to comply with API rate-limiting, sleep here for 1/10th of a second
			time.sleep(0.1)
			logging.info("Found %d breaches for %s", len(breaches), email)
			all_breaches[email] = breaches
			if save:
				save_breaches(breaches_fname, all_breaches)
		except EmailNotFoundError:
			logging.warning("No breaches found for %s", email)
	if save:
		print(f"breaches saved in {breaches_fname}")
	else:
		logging.warning("breaches not saved to disk")


def find_password_matches(ignore_pins: bool = True):
	"""Matches the downloaded sha1 passwords with HIBP password database"""
	with open(PASSWORD_HASH_FILE) as fp:
		contents = json.load(fp)
		for account, entry in contents.items():
			if ignore_pins and entry["is_numeric"]:
				logging.debug("Skipping entry %s - password is numeric only and is likely a PIN", account)
				continue
			password_hash = entry["sha1"]
			prefix = password_hash[:5]
			range_response = HIBP.get_password_range(prefix)
			# this makes sure we are compliant with HIBP rate-limiting
			time.sleep(0.1)
			# print(repr(range_response))
			count = 0
			has_match = False
			for line in range_response.split("\r\n"):
				count += 1
				h, freq = line.split(":")
				if (prefix + h.lower()) == password_hash:
					logging.warning("Match on password for account %s", account)
					has_match = True
					break
			if not has_match:
				logging.debug("No match for account %s", account)
			# print(count)


class HIBP:
	HEADERS = {
		"User-Agent": "passzero-password-manager"
	}

	@classmethod
	def get_password_range(cls, first_5_hash_chars: str) -> str:
		"""
		See https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange
		"""
		assert isinstance(first_5_hash_chars, str)
		assert len(first_5_hash_chars) == 5
		url = f"https://api.pwnedpasswords.com/range/{first_5_hash_chars}"
		r = requests.get(
			url,
			headers=HIBP.HEADERS
		)
		if r.ok:
			return r.text
		else:
			print(r.status_code)
			logging.critical("Failed to get ranged passwords for %s", first_5_hash_chars)
			print(r.text)
			exit(1)


if __name__ == "__main__":
	parser = ArgumentParser()
	parser.add_argument("command", choices=[
		"passwords",
		"breaches"
	],
	help="""passwords - looks for matching passwords in HIBP
	breaches - get breaches for all your passzero usernames
	""")
	parser.add_argument("-u", "--username", required=True,
		help="Username used to login to passzero")
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
		help="Password used to login to passzero")
	parser.add_argument("--no-ignore-pins", action="store_true", default=False,
		help="By default ignore passwords which are all digits. By setting this option also perform checks for all-digit passwords.")

	# parser.add_argument("--check-passwords", action="store_true",
	# 	help="Check all the passwords held in passzero against passwords in HIBP")
	args = parser.parse_args()
	setup_logging(args.verbose)
	if args.command == "passwords":
		if not os.path.exists(PASSWORD_HASH_FILE):
			master_password = getpass.getpass()
			download_sha1_password_hashes(args.username, master_password)
		else:
			logging.debug("Using cached password hashes")
		find_password_matches(not args.no_ignore_pins)
	elif args.command == "breaches":
		if not os.path.exists(USERNAME_FILE):
			password = getpass.getpass()
			download_usernames(args.username, password)
		usernames = read_usernames(USERNAME_FILE)
		emails = filter(is_email, usernames)
		get_breaches_for_emails(emails)
		# non_email_usernames = [username for username in usernames if not is_email(username)]
		# get_breaches_for_emails(non_email_usernames, False)
		# with open(USERNAME_FILE) as fp:
		# 	contents = json.load(fp)
		# 	pprint(contents)
	else:
		logging.critical("Unknown command: %s", args.command)
		exit(1)
