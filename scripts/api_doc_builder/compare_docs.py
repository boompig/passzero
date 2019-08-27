import sys
from bs4 import BeautifulSoup

def compare():
    l = []
    for arg in sys.argv[1:]:
        with open(arg) as fp:
            contents = fp.read()
            soup = BeautifulSoup(contents, "html.parser")
            l.append(soup)

    assert l[0].prettify() == l[1].prettify()

def bs_prettify():
    with open(sys.argv[1]) as fp:
            contents = fp.read()
            soup = BeautifulSoup(contents, "html.parser")
            print(soup.prettify())

bs_prettify()
