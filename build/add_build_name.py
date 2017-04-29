from argparse import ArgumentParser
import os
import random
import sys


DIRNAME = os.path.dirname(os.path.realpath(__file__))
ANIMALS_FILE = os.path.join(DIRNAME, "animals.txt")
ADJ_FILE = os.path.join(DIRNAME, "adjectives.txt")


def replace_first_line(fname, new_line):
    with open(fname) as f:
        lines = f.readlines()
    if len(lines) > 0:
        lines[0] = new_line + "\n";
    else:
        lines.append(new_line + "\n")
    with open(fname, "w") as f:
        for line in lines:
            f.write(line)


def get_build_name(animals, adj):
    return "%s_%s" % (random.choice(adj), random.choice(animals))


def read_list(fname):
    l = []
    with open(fname, "r") as f:
        for line in f:
            l.append(line.strip())
    return l


if __name__ == "__main__":
    animals = read_list(ANIMALS_FILE)
    adj = read_list(ADJ_FILE)
    build_name = get_build_name(animals, adj)
    parser = ArgumentParser()
    parser.add_argument("fname")
    args = parser.parse_args()
    assert os.path.exists(args.fname), "%s does not exist" % args.fname
    line = "BUILD_ID = \"%s\"" % build_name
    replace_first_line(args.fname, line)
    print "set build ID to %s" % build_name
