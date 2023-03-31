import json
import os


def read_build_name() -> str:
    file_dir = os.path.dirname(__file__)
    base_dir = os.path.abspath(os.path.join(file_dir, ".."))
    config_file = os.path.join(base_dir, "config/config.json")
    assert os.path.exists(config_file)
    with open(config_file, "r") as fp:
        config = json.load(fp)
        return config["BUILD_ID"]


SALT_SIZE = 32
TOKEN_SIZE = 32
DEFAULT_ENTRY_VERSION = 5
# in string characters
ENTRY_LIMITS = {
    "account": 100,
    "username": 100,
    "password": 256,
    "extra": 4096
}


class DefaultConfig:
    BUILD_ID = read_build_name()
    PORT = 5050
