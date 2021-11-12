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


BUILD_ID = read_build_name()
SALT_SIZE = 32
PORT = 5050
TOKEN_SIZE = 32
CSRF_TOKEN_LENGTH = 64
DEFAULT_ENTRY_VERSION = 5
