import json
import os
import random
from argparse import ArgumentParser
from typing import List

DIRNAME = os.path.dirname(os.path.realpath(__file__))
ANIMALS_FILE = os.path.join(DIRNAME, "animals.txt")
ADJ_FILE = os.path.join(DIRNAME, "adjectives.txt")


def update_config_file(config_file_path: str, build_name: str):
    with open(config_file_path, "r") as f:
        config = json.load(f)
        config["BUILD_ID"] = build_name
    with open(config_file_path, "w") as f:
        json.dump(config, f, indent=4, sort_keys=True)


def get_build_name(animals: List[str], adj: List[str]) -> str:
    return "%s_%s" % (random.choice(adj), random.choice(animals))


def read_list(fname: str) -> List[str]:
    l = []
    with open(fname, "r") as f:
        for line in f:
            if not line.startswith("#"):
                l.append(line.strip())
    return l


if __name__ == "__main__":
    animals = read_list(ANIMALS_FILE)
    adj = read_list(ADJ_FILE)
    build_name = get_build_name(animals, adj)

    parser = ArgumentParser()
    parser.add_argument("fname", help="Path to the config file")
    args = parser.parse_args()

    assert os.path.exists(args.fname), "%s does not exist" % args.fname
    update_config_file(args.fname, build_name)
    print("set build ID to %s" % build_name)
