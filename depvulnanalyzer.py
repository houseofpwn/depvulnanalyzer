import json
import sys


def loaddeps(depfile):
    print("Loading dependencies...")
    with open(depfile, "r") as f:
        deps = json.load(f)
        f.close()
    return deps

def loadnotfixed(notfixedfile):
    print("Loading not fixed dependencies...")
    with open(notfixedfile, "r") as f:
        notfixed = json.load(f)
        f.close()
    return notfixed

def main():
    depfile = sys.argv[1]
    notfixedfile = sys.argv[2]
    deps = loaddeps(depfile)
    notfixed = loadnotfixed(notfixedfile)
    print("Done...")


if __name__ == "__main__":
    main()

