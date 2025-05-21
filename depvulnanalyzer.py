import json
import sys
from itertools import filterfalse
from operator import truediv

from colorama import Fore, Back, Style
import re

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

def loadfixed(fixedfile):
    print(Fore.YELLOW + "Loading fixed dependencies...")
    with open(fixedfile, "r") as f:
        fixed = json.load(f)
        f.close()
    return fixed

def isdepvulnerable(name, vuln, deps):
    for dep in deps:
        #print(f'Checking for {name} in {dep}')
        deplist = deps[dep]
        if name in deplist:
            print(Fore.LIGHTWHITE_EX + "Module ",  Fore.WHITE + dep, Fore.RED + name)

def isbetweenversions(low, high, current):
    #print(Fore.WHITE + f'Checking if {low} < {current} < {high}')
    lowlist = re.split(r'[.-]', low)
    highlist = re.split(r'[.-]', high)
    currentlist = re.split(r'[.-]', current)
    failed = False
    index = 0
    minmet = True
    for v in currentlist:
        if index > len(lowlist) - 1:
            lowtemp = '0'
        else:
            lowtemp = lowlist[index]
        if ( int(v) < int(lowtemp)):
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
            #print(Fore.WHITE + f'[ {low} - {high} ] (', Fore.RED + f'{current}', Fore.WHITE + ')')
        else:
            failed = False
            #print(Fore.WHITE + f'[ {low} - {high} ] (', Fore.GREEN + f'{current}', Fore.WHITE + ')')
    else:
        failed = False
        #print(Fore.WHITE + f'[ {low} - {high} ] (', Fore.GREEN + f'{current}', Fore.WHITE + ')')
    return failed
    #if failed:
    #    print(Fore.RED + f'{low} <= {current} < {high}')
    #else:
    #    print(Fore.GREEN + f'{current} not affected.')


def checkdepfixed(name, vuln, deps):
    lastname = "xx"
    for dep in deps:
        deplist = deps[dep]
        if name in deplist:
            depver = deplist[name].replace("v", "")
            low = vuln["introduced"]
            high = vuln["fixed"]
            current = depver
            failed = isbetweenversions(vuln["introduced"], vuln["fixed"], depver)
            if failed:
                if lastname !=name:
                    print(Fore.WHITE + f'Library {name}')
                print(Fore.WHITE + f'\tModule {dep} - [ {low} - {high} ] (', Fore.RED + f'{current}', Fore.WHITE + ')')
            else:
                if lastname !=name:
                    print(Fore.WHITE + f'Library {name}')
                print(Fore.WHITE + f'\tModule {dep} - [ {low} - {high} ] (', Fore.GREEN + f'{current}', Fore.WHITE + ')')
            lastname = name

def checkunfixedvulns(deps, notfixed):
    print(Fore.BLUE + "Checking vulnerabilities...")
    for cve, libobjs in notfixed.items():
        for item in libobjs:
            if type(libobjs[item]) is dict:
                isdepvulnerable(item, libobjs[item], deps)
        #print(f'{cve} ')

def checkfixedvulns(deps, fixed):
    print(Fore.YELLOW + "Checking fixed vulnerabilities...")
    for cve, libobjs in fixed.items():
        for item in libobjs:
            if type(libobjs[item]) is dict:
                checkdepfixed(item, libobjs[item], deps)

def main():
    depfile = sys.argv[1]
    docsdir = sys.argv[2]
    deps = loaddeps(depfile)
    notfixed = loadnotfixed(f'{docsdir}/notfixed.json')
    fixed = loadfixed(f'{docsdir}/fixed.json')
    checkunfixedvulns(deps, notfixed)
    checkfixedvulns(deps, fixed)
    print(Fore.GREEN + "Done...")


if __name__ == "__main__":
    main()

