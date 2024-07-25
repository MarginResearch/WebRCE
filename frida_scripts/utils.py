from shutil import which
RED = '\033[0;31m'
NC = '\033[0m'
BLUE = '\033[0;34m'
GREEN = '\033[0;32m'


def log(s: str, level: str = "", indent: int = 0):
    """
    logging function. options are "" (normal), "err" for Error, and "debug"
    """
    if level == "debug":
        print(f"{BLUE}" + indent * " " + "[-] " + s + f"{NC}")
    elif level == "err":
        print(f"{RED}" + indent * " " + "[!] " + s + f"{NC}")
    else:
        print(f"{GREEN}" + indent * " " + "[+] " + s + f"{NC}")


def check_for_utility(name: str):
    utility = which(name)
    if not utility:
        if name == "ipsw":
            url = "https://github.com/blacktop/ipsw"
        elif name == "ROPGadget":
            url = "python3 -m pip install ROPgadget"
        else:
            url = ""
        log("Install " + name + " tool and add to path: " + url, "err")
        exit(1)
