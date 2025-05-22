import json
import sys

from colorama import Fore
import re

def loaddeps(depfile):
    print(Fore.YELLOW + "Loading dependencies...")
    try:
        with open(depfile, "r") as f:
            deps = json.load(f)
            f.close()
    except FileNotFoundError:
        print(f'File {depfile} not found')
        exit(1)
    return deps

def loadnotfixed(notfixedfile):
    print(Fore.CYAN + "Loading non-fixed dependencies...")
    try:
        with open(notfixedfile, "r") as f:
            notfixed = json.load(f)
            f.close()
    except FileNotFoundError:
        print(f'File {notfixedfile} not found')
        exit(1)
    return notfixed

def loadfixed(fixedfile):
    print(Fore.YELLOW + "Loading fixed dependencies...")
    try:
        with open(fixedfile, "r") as f:
            fixed = json.load(f)
            f.close()
    except FileNotFoundError:
        print(f'File {fixedfile} not found')
        exit(1)
    return fixed

def isdepvulnerable(name, deps, notfixedstatus):
    for dep in deps:
        deplist = deps[dep]
        if name in deplist:
            status = {
                "library" : name,
                "module": dep,
                "current": deplist[name]
            }
            notfixedstatus.append(status)
            print(Fore.LIGHTWHITE_EX + "Module ",  Fore.WHITE + dep, Fore.RED + name + ' '
                  + Fore.WHITE + '( ' + Fore.RED + deplist[name] + ' ' + Fore.WHITE + ')')
    return notfixedstatus

def isbetweenversions(low, high, current):
    lowlist = re.split(r'[.-]', low)
    highlist = re.split(r'[.-]', high)
    currentlist = re.split(r'[.-]', current)
    index = 0
    minmet = True
    for v in currentlist:
        if index > len(lowlist) - 1:
            lowtemp = '0'
        else:
            lowtemp = lowlist[index]
        if int(v) < int(lowtemp):
            minmet = False
            break
        index += 1
    if minmet:
        index = 0
        maxmet = False
        for v in currentlist:
            if index > len(highlist) - 1:
                hightemp = '0'
            else:
                hightemp = highlist[index]
            if int(v) < int(hightemp):
                maxmet = True
                break
            if int(v) > int(hightemp):
                maxmet = False
                break
            index += 1
        if maxmet:
            failed = True
        else:
            failed = False
    else:
        failed = False
    return failed

def checkdepfixed(name, vuln, deps, fixedstatus, docsdir):
    # This is a sentinel for the upcoming loop for formatting.
    lastname = "xx"
    for dep in deps:
        deplist = deps[dep]
        if name in deplist:
            depver = deplist[name].replace("v", "")
            low = vuln["introduced"]
            high = vuln["fixed"]
            current = depver
            failed = isbetweenversions(vuln["introduced"], vuln["fixed"], depver)
            status = {
                "library" : name,
                "module": dep,
                "fixver": high,
                "current": current
            }
            if failed:
                if lastname !=name:
                    print(Fore.WHITE + f'Library {name}')
                status["vulnerable"] = True
                print(Fore.WHITE + f'\tModule ' + Fore.LIGHTWHITE_EX + f'{dep} - ' + Fore.YELLOW + f'[ {low} - {high} ] ' + Fore.WHITE + f'(', Fore.RED + f'{current}', Fore.WHITE + ')')
            else:
                if lastname !=name:
                    print(Fore.WHITE + f'Library {name}')
                status["vulnerable"] = False
                print(Fore.WHITE + f'\tModule ' + Fore.LIGHTWHITE_EX + f'{dep} - ' + Fore.YELLOW + f'[ {low} - {high} ] ' + Fore.WHITE + f'(', Fore.GREEN + f'{current}', Fore.WHITE + ')')
            fixedstatus.append(status)
            lastname = name

    with open(f'{docsdir}/notfixed-status.json', "w+") as f:
        json.dump(fixedstatus, f, indent=4)
        f.close()

def checkunfixedvulns(deps, notfixed, docsdir):
    print(Fore.BLUE + "Checking not-fixed vulnerabilities...")
    notfixedstatus = []
    for cve, libobjs in notfixed.items():
        for item in libobjs:
            if type(libobjs[item]) is dict:
                notfixedstatus = isdepvulnerable(item, deps, notfixedstatus)
    with open(f'{docsdir}/fixed-status.json', "w+") as f:
        json.dump(notfixedstatus, f, indent=4)
        f.close()

def checkfixedvulns(deps, fixed, docsdir):
    print(Fore.BLUE + "Checking fixed vulnerabilities...")
    fixedstatus = []
    for cve, libobjs in fixed.items():
        for item in libobjs:
            if type(libobjs[item]) is dict:
                checkdepfixed(item, libobjs[item], deps, fixedstatus, docsdir)
    return fixedstatus

def main():
    depfile = sys.argv[1]
    docsdir = sys.argv[2]
    deps = loaddeps(depfile)
    notfixed = loadnotfixed(f'{docsdir}/notfixed.json')
    fixed = loadfixed(f'{docsdir}/fixed.json')
    checkfixedvulns(deps, fixed, docsdir)
    checkunfixedvulns(deps, notfixed, docsdir)
    print(Fore.WHITE + "Done...")

if __name__ == "__main__":
    main()

