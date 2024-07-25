from dataclasses import dataclass
import json
import os
import pathlib
from pwn import *
import shutil
import subprocess
import tempfile
import typing
import utils
import zipfile


def find_symbols_with_json(dsc_cache_path: str, symbols: typing.List[typing.Dict[str, str]]) \
        -> typing.Dict[str, int]:
    """
    Find symbols from a DSC dylib using the JSON flag
    :param dsc_cache_path: Path to the DSC
    :param symbols A list of dictionaries with at least the "pattern" key containing a regex to find, and "image" to
                  specify the dylib. "name" can be set to set the output dictionary key for each offset
    :return A dictionary of name and address for each symbol
    """
    try:
        with tempfile.NamedTemporaryFile(mode="w") as symbol_input:
            json.dump(symbols, symbol_input)
            symbol_input.flush()
            with tempfile.NamedTemporaryFile() as ntf:
                subprocess.run(["ipsw", "dyld", "symaddr",
                                dsc_cache_path, "--in", symbol_input.name, "--out",
                                ntf.name], check=True,
                               capture_output=True)
                with open(ntf.name, "r") as fp:
                    syms = json.load(fp)
                    return {entry['name']: entry['address'] for entry in syms}
    except Exception as ex:
        utils.log(f"Received exception {str(ex)} trying to find symbols", "err")
        exit(1)


def find_macho_addr_nm(macho_path: str, regex: str) -> int:
    """
    nm command is faster for finding exports and globals
    @param macho_path: The macho to parse
    @param regex: The symbol to locate
    :return The symbol to locale
    """
    try:
        run = subprocess.run(["nm", macho_path], check=True,
                             capture_output=True)
        run = subprocess.run(["grep", "-E", regex],
                             capture_output=True, input=run.stdout, check=True)
        run = subprocess.run(["sed", "-n", "1 p"],
                             capture_output=True, input=run.stdout, check=True)
        run = subprocess.run(["cut", "-d", " ", "-f1"],
                             capture_output=True, input=run.stdout, check=True)
        return int(run.stdout.decode(), 16)
    except Exception as ex:
        utils.log(f"Received exception {str(ex)} trying to find symbol {regex} in macho {macho_path} with nm", "err")
        exit(1)


def find_macho_addr_ipsw(macho_path: str, regex: str) -> int:
    """
    Find address in the macho file
    :param macho_path: The macho to search
    :param regex: A regular expression to match the symbol
    :return The symbol offset
    """
    try:
        run = subprocess.run(["ipsw", "macho", "info", "-n",
                              "--no-color", macho_path], check=True,
                             capture_output=True)
        run = subprocess.run(["grep", "-E", regex],
                             capture_output=True, input=run.stdout, check=True)
        run = subprocess.run(["sed", "-n", "1 p"],
                             capture_output=True, input=run.stdout, check=True)
        run = subprocess.run(["cut", "-d", ":", "-f1"],
                             capture_output=True, input=run.stdout, check=True)
        return int(run.stdout.decode(), 16)
    except Exception as ex:
        utils.log(f"Received exception {str(ex)} trying to find symbol {regex} in macho {macho_path} with ipsw",
                  "err")
        exit(1)


def find_macho_addr_otool(macho_path: str, regex: str) -> int:
    """
    Find address in the macho file where nm fails, faster than ipsw
    :param macho_path: The macho to search
    :param regex: A regular expression to match the symbol
    :return The symbol offset
    """
    try:
        run = subprocess.run(["otool", "-o", macho_path], capture_output=True,
                             check=True)
        run = subprocess.run(["grep", regex, "-A", "1"], capture_output=True,
                             input=run.stdout, check=True)
        run = subprocess.run(["sed", "-n", "2 p"], capture_output=True,
                             input=run.stdout, check=True)
        run = subprocess.run(["cut", "-d", " ", "-f1"], capture_output=True,
                             input=run.stdout, check=True)
        return int(run.stdout.decode(), 16)
    except Exception as ex:
        utils.log(f"Received exception {str(ex)} trying to find symbol {regex} in macho {macho_path}, with otool",
                  "err")
        exit(1)


def find_macho_addr_after_otool(macho_path: str, func_regex: str, after_regex: str, idx: int = 1) -> int:
    """
    Find an address in function `func_regex` after the `after_regex` instruction.
    Searches for the first occurrence of the `after_regex` string and parses the
    address immediately following. A later occurrence of the string is configurable
    using the `idx` parameter.
    :param macho_path: The macho to search
    :param func_regex: A regular expression to match the function
    :param after_regex: A regular expression to match and find the address immediately following
    :param idx: The nth occurrence of the `after_regex` string to find (default is 1st)
    :return The symbol offset
    """
    try:
        # grep `after_regex` -A 1 return three lines per match, always want the middle row per occurrence
        #     <after_regex> instruction        matched line
        #     instruction after                target of this function
        #     --                               end of match indicator
        idx = 3 * idx - 1
        run = subprocess.run(["otool", "-tv", "-p", func_regex, macho_path],
                             capture_output=True, check=True)
        run = subprocess.run(["grep", after_regex, "-A", "1"], capture_output=True,
                             input=run.stdout, check=True)
        run = subprocess.run(["sed", "-n", str(idx) + " p"], capture_output=True,
                             input=run.stdout, check=True)
        run = subprocess.run(["cut", "-d", "\t", "-f1"], capture_output=True,
                             input=run.stdout, check=True)
        return int(run.stdout.decode(), 16)
    except Exception as ex:
        utils.log(f"Received exception {str(ex)} trying to find symbol after {after_regex} in macho {macho_path}, with otool",
                  "err")
        exit(1)


def find_stub_addr_otool(macho_path: str, func_regex: str) -> int:
    """
    Find the address of a stub function by `grep`ping through disassembly.
    :param macho_path: The macho to search
    :param func_regex: A regular expression to match the function
    :return The stub function address
    """
    try:
        run = subprocess.run(["otool", "-tv", macho_path],
                             capture_output=True, check=True)
        run = subprocess.run(["grep", func_regex], capture_output=True,
                             input=run.stdout, check=True)
        run = subprocess.run(["sed", "-n", "1 p"], capture_output=True,
                             input=run.stdout, check=True)
        run = subprocess.run(["cut", "-d", "\t", "-f3"], capture_output=True,
                             input=run.stdout, check=True)
        run = subprocess.run(["cut", "-d", " ", "-f1"], capture_output=True,
                             input=run.stdout, check=True)
        return find_got_addr(macho_path, int(run.stdout.decode(), 16))
    except Exception as ex:
        utils.log(f"Received exception {str(ex)} trying to find stub symbol {func_regex} in macho {macho_path}, with otool",
                  "err")
        exit(1)


def find_got_addr(macho_path: str, addr: int) -> int:
    """
    Find the GOT address for a function from the stub function which loads it
    :param macho_path: The macho to search
    :param addr: The address of a ADRP ; LDR instruction stub that loads the GOT address
    :return The GOT address loaded by the stub
    """
    try:
        context.arch = "arm64"
        context.bits = 64
        context.endian = "little"
        f = open(macho_path, "rb")
        data = f.read()
        idx = addr - 0x100000000
        adrp = disasm(data[idx:idx+4])
        off1 = int(adrp.split(" ")[-1], 16)
        ldr = disasm(data[idx+4:idx+8])
        off2 = int(ldr.split("#")[-1].replace("]", ""))
        return (addr & ~0xfff) + off1 + off2
    except Exception as ex:
        utils.log(f"Received exception {str(ex)} trying to find GOT addr for call at {hex(addr)} in macho {macho_path}, with otool",
                  "err")
        exit(1)


class SystemOffsetFinder:
    __slots__ = ["_ipsw", "__dsc", "__extract_dir", "offsets"]

    def __init__(self, ipsw_file: str):
        """
        :param ipsw_file: The IPSW to parse
        """
        self._ipsw: str = ipsw_file
        self.__dsc: typing.Optional[str] = None
        self.__extract_dir = "/tmp/extract"
        self.offsets: typing.Optional[SystemOffsets] = None

    def extract_dsc(self):
        utils.check_for_utility("ipsw")
        # Extract shared cache to tmp directory #
        utils.log("Extracting ipsw dyld shared cache")
        os.makedirs(self.__extract_dir, exist_ok=True)
        subprocess.run(["ipsw", "extract", self._ipsw, "--dyld", "-o", self.__extract_dir], check=True)

        self.__dsc = next(pathlib.Path(self.__extract_dir).glob("*/dyld_shared_cache_arm64e"), None)

        if not self.__dsc:
            raise FileNotFoundError("Something went wrong when extracting the shared cache")

    def find_offsets(self) -> None:
        symbols = [
            {"name": "_open$NOCANCEL", "pattern": "^_open\\$NOCANCEL$", "type": "regular",
             "image": "libsystem_kernel.dylib"},
            {"name": "_mmap", "pattern": "^_mmap$", "type": "regular", "image": "libsystem_kernel.dylib"},
            {"name": "_NXArgv", "pattern": "^_NXArgv$", "type": "regular", "image": "libdyld.dylib"},
            {"name": "'_OBJC_CLASS_$_NSString", "pattern": "^_OBJC_CLASS_\\$_NSString$", "type": "regular",
             "image": "Foundation"},
            {"name": "UIApp", "pattern": "^_UIApp$", "type": "regular",
             "image": "UIKitCore"}
        ]
        try:
            if not self.__dsc:
                self.extract_dsc()

            offsets = find_symbols_with_json(self.__dsc, symbols)

            self.offsets = SystemOffsets(offsets["_NXArgv"], offsets["_OBJC_CLASS_$_NSString"],
                                         offsets["_mmap"], offsets["_open$NOCANCEL"], offsets["_UIApp"])

        finally:
            shutil.rmtree(self.__extract_dir)
            for file in filter(lambda entry: entry.endswith(".dmg"), os.listdir(".")):
                os.remove(file)


class SignalOffsetFinder:
    __slots__ = ["__ipa", "macho", "frameworks", "offsets"]

    def __init__(self, ipa_file: str):
        """
        :param ipa_file: The IPA file to open
        """
        self.__ipa = ipa_file
        self.macho = tempfile.NamedTemporaryFile(mode="wb")
        self.__load_application()
        self.frameworks = self.__unpack_frameworks(["Payload/Signal.app/Frameworks/SignalServiceKit.framework/"
                                                    "SignalServiceKit",
                                                    "Payload/Signal.app/Frameworks/WebRTC.framework/WebRTC"])

        self.offsets: typing.Optional[SignalOffsets] = None

    def __unpack_frameworks(self, frameworks: typing.List[str]) -> typing.Dict[str, tempfile.NamedTemporaryFile]:
        """
        Unpack one or more frameworks, storing them in a temp file
        :param frameworks: A list of paths (absolute to IPA zip) of framework binaries
        :return Dictionary of <path, tempfile file handler>
        """
        unpacked_frameworks = {path: tempfile.NamedTemporaryFile(mode="wb") for path in frameworks}
        with zipfile.ZipFile(self.__ipa, "r") as zf:
            for framework in unpacked_frameworks.keys():
                try:
                    with zf.open(framework) as framework_zf:
                        unpacked_frameworks[framework].write(framework_zf.read())
                        utils.log(f"Unpacked {framework} to {unpacked_frameworks[framework].name}", "debug")
                except KeyError as e:
                    print(f"Failed to find framework {framework}: {e.args[0]}")
                    if os.path.exists(unpacked_frameworks[framework].name):
                        unpacked_frameworks[framework].close()
                        os.unlink(unpacked_frameworks[framework].name)
                    exit(1)
        return unpacked_frameworks

    def __load_application(self):
        with zipfile.ZipFile(self.__ipa, "r") as zf:
            with zf.open("Payload/Signal.app/Signal") as macho:
                self.macho.write(macho.read())
                utils.log(f"Signal macho at {self.macho.name}", "")

    def find_offsets(self) -> None:
        mode_ipsw = 1
        mode_otool = 2
        mode_otool_after = 3
        mode_otool_stub = 4
        symbols = [
            {"name": "_OBJC_METACLASS_.__TtC6Signal11AppDelegate", "image": None},
            {"name": "s16SignalServiceKit14SSKEnvironmentCMa",
             "image": None, "mode": mode_otool_stub},
            {"name": "s16SignalServiceKit14SSKEnvironmentCMa",
             "image": "SignalServiceKit"},
            {"name": "s16SignalServiceKit14SSKEnvironmentC7_shared33_EEC8B08E64177A87B63E94E9361FDCEALLACSgvpZ",
             "image": "SignalServiceKit"},
            {"name": "__objc_classrefs",
             "image": "WebRTC", "mode": mode_otool},
            {"name": "__ZTVN6webrtc13RealTimeClockE",
             "image": "WebRTC"},
            {"name": "__ZN6webrtc12RTCPReceiver14IncomingPacketEN3rtc9ArrayViewIKhLln4711EEE",
             "after": "__ZN6webrtc12RTCPReceiver30TriggerCallbacksFromRtcpPacketERKNS0_17PacketInformationE",
             "image": "WebRTC", "mode": mode_otool_after},
        ]

        offsets = []
        for symbol_lookup in symbols:
            if not symbol_lookup["image"]:
                framework = self.macho
            else:
                framework = next((self.frameworks[fw] for fw in self.frameworks
                                  if fw.endswith(symbol_lookup["image"])), None)

                if not framework:
                    raise ValueError(f"Failed to find unpacked framework with name {symbol_lookup['image']}")

            utils.log(f"Looking up {symbol_lookup['name']} in {symbol_lookup['image'] or 'main binary'} "
                      f"({framework.name})", "debug")

            if symbol_lookup.get("mode", 0) == mode_ipsw:
                offsets.append(find_macho_addr_ipsw(framework.name, symbol_lookup["name"]))
            elif symbol_lookup.get("mode", 0) == mode_otool:
                offsets.append(find_macho_addr_otool(framework.name, symbol_lookup["name"]))
            elif symbol_lookup.get("mode", 0) == mode_otool_after:
                offsets.append(find_macho_addr_after_otool(framework.name, symbol_lookup["name"],
                                                           symbol_lookup["after"]))
            elif symbol_lookup.get("mode", 0) == mode_otool_stub:
                offsets.append(find_stub_addr_otool(framework.name, symbol_lookup["name"]))
            else:
                offsets.append(find_macho_addr_nm(framework.name, symbol_lookup['name']))

        self.offsets = SignalOffsets(*offsets)


@dataclass
class SignalOffsets:
    AppDelegateOffset: int
    SSKEnvironmentMeta: int
    ServiceSSKEnvironmentMeta: int
    ServiceEnvironment: int
    ObjcClassrefsOffset: int
    RealTimeClockVtableOffset: int
    IncomingPacketReturn: int


@dataclass
class SystemOffsets:
    NXArgv: int
    NSString: int
    mmap: int
    opennocancel: int
    UIApp: int


if __name__ == "__main__":
    x = SignalOffsetFinder("/path/to/Signal.ipa")
    x.find_offsets()
    print(x)
