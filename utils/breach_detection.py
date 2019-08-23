import logging
from argparse import ArgumentParser
import hashlib
import requests
from tests.unit_tests import api
import getpass
import json
import os
from typing import Set, List, Dict, Iterable
from pprint import pprint


def setup_logging(verbose: bool):
	log_level = (logging.DEBUG if verbose else logging.INFO)
	logging.basicConfig(
		level=log_level,
		format="[%(levelname)s] %(message)s"
	)


def save_usernames(usernames: Set[str]) -> str:
	try:
		os.mkdir("data")
	except IOError:
		pass
	fname = "data/usernames.json"
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


def download_usernames(username: str, password: str):
	session = requests.Session()
	apiv3 = api.ApiV3(session)
	logging.debug("Logging in with %s", username)
	try:
		apiv3.login(username, password)
	except api.BadStatusCodeException:
		logging.critical("Failed to login")
		exit(1)
	logging.debug("Successfully logged in")
	entries = apiv3.get_encrypted_entries()
	logging.info(f"Got {len(entries)} encrypted entries")
	logging.info("Decrypting entries...")
	dec_entries = {}
	for entry in entries:
		entry_id = entry["id"]
		logging.debug(f"Decrypting entry {entry_id}")
		dec_entries[entry_id] = apiv3.decrypt_entry(entry_id)
	logging.info("Decrypted all entries")
	usernames = set([])
	for entry_id, dec_entry in dec_entries.items():
		usernames.add(dec_entry["username"])
	username_fname = save_usernames(usernames)
	logging.info("Saved usernames in %s", username_fname)


def download_sha1_password_hashes(username: str, master_password: str) -> Dict:
	session = requests.Session()
	apiv3 = api.ApiV3(session)
	logging.debug("Logging in with %s", username)
	try:
		apiv3.login(username, master_password)
	except api.BadStatusCodeException:
		logging.critical("Failed to login")
		exit(1)
	logging.debug("Successfully logged in")
	entries = apiv3.get_encrypted_entries()
	logging.info(f"Got {len(entries)} encrypted entries")
	logging.info("Decrypting entries...")
	dec_entries = {}
	for entry in entries:
		entry_id = entry["id"]
		logging.debug(f"Decrypting entry {entry_id}")
		dec_entries[entry_id] = apiv3.decrypt_entry(entry_id)
	logging.info("Decrypted all entries")
	hashed_passwords = {}
	for entry_id, dec_entry in dec_entries.items():
		if dec_entry["password"] == "":
			continue
		h = hashlib.sha1()
		h.update(dec_entry["password"].encode('utf-8'))
		hashed_passwords[dec_entry["account"]] = h.hexdigest()
	print(json.dumps(hashed_passwords, indent=4))
	return hashed_passwords
	# logging.info("Saved usernames in %s", username_fname)


class EmailNotFoundError(Exception):
	pass


def get_breaches_per_email(email: str) -> dict:
	headers = {
		"User-Agent": "passzero-password-manager"
	}
	r = requests.get(f'https://haveibeenpwned.com/api/v2/breachedaccount/{email}', headers=headers)
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


class HIBP:
	HEADERS = {
		"User-Agent": "passzero-password-manager"
	}

	@classmethod
	def get_password_range(cls, first_5_hash_chars: str) -> List[str]:
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
	])
	parser.add_argument("-u", "--username", required=True,
		help="Username used to login to passzero")
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
		help="Password used to login to passzero")

	# parser.add_argument("--check-passwords", action="store_true",
	# 	help="Check all the passwords held in passzero against passwords in HIBP")
	args = parser.parse_args()
	setup_logging(args.verbose)
	if args.command == "passwords":
		# master_password = getpass.getpass()
		# download_sha1_password_hashes(args.username, master_password)
		# exit(0)
		with open("data/password_hashes.json") as fp:
			contents = json.load(fp)
			for account, password_hash in contents.items():
				prefix = password_hash[:5]
				range_response = HIBP.get_password_range(prefix)
				# print(repr(range_response))
				count = 0
				for line in range_response.split("\r\n"):
					count += 1
					h, freq = line.split(":")
					if (prefix + h.lower()) == password_hash:
						print(account)
						print("match")
				# print(count)
	elif args.command == "breaches":
		# download_usernames(args.username, password)
		# usernames = read_usernames("data/usernames.json")
		# emails = filter(is_email, usernames)
		# get_breaches_for_emails(emails)
		# non_email_usernames = [username for username in usernames if not is_email(username)]
		# get_breaches_for_emails(non_email_usernames, False)
		with open("data/breaches.json") as fp:
			contents = json.load(fp)
			pprint(contents)
	else:
		logging.critical("Unknown command: %s", args.command)
		exit(1)
