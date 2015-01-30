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

    if len(sys.argv) > 1:
        fname = sys.argv[1]
        line = "{%%- set css_build_id = \"%s\" -%%}" % build_name
        replace_first_line(fname, line)
        print "set css_build_id to %s" % build_name
    else:
        print "specify file"
