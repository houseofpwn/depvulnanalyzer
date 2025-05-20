import json
import sys
from colorama import Fore, Back, Style

def loaddeps(depfile):
    print(Fore.YELLOW + "Loading dependencies...")
    with open(depfile, "r") as f:
        deps = json.load(f)
        f.close()
    return deps

def loadnotfixed(notfixedfile):
    print(Fore.CYAN + "Loading non-fixed dependencies...")
    with open(notfixedfile, "r") as f:
        notfixed = json.load(f)
        f.close()
    return notfixed

def isdepvulnerable(name, vuln, deps):
    for dep in deps:
        #print(f'Checking for {name} in {dep}')
        deplist = deps[dep]
        if name in deplist:
            print(Fore.RED + name)

def checkvulns(deps, notfixed):
    print(Fore.BLUE + "Checking vulnerabilities...")
    for cve, libobjs in notfixed.items():
        for item in libobjs:
            if type(libobjs[item]) is dict:
                isdepvulnerable(item, libobjs[item], deps)
        #print(f'{cve} ')


def main():
    depfile = sys.argv[1]
    notfixedfile = sys.argv[2]
    deps = loaddeps(depfile)
    notfixed = loadnotfixed(notfixedfile)
    checkvulns(deps, notfixed)
    print(Fore.WHITE + "Done...")


if __name__ == "__main__":
    main()

