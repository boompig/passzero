from typing import Optional, Dict, Any


def get_test_decrypted_entry(i: Optional[int] = None) -> Dict[str, Any]:
    if i is None:
        return {
            "account": f"test account",
            "username": f"test username",
            "password": f"test password",
            "has_2fa": False,
            "extra": f"test extra"
        }
    else:
        return {
            "account": f"test account {i}",
            "username": f"test username {i}",
            "password": f"test password {i}",
            "has_2fa": i % 2 == 0,
            "extra": f"test extra {i}"
        }


def assert_decrypted_entries_equal(actual: dict, expected: dict) -> None:
    for field in ["account", "username", "password", "extra", "has_2fa"]:
        print(actual)
        print(expected)
        assert actual[field] == expected[field], "Failed entry validation for field %s" % field
