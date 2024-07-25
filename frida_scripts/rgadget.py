class Register:
    def __init__(self, name: str, idx: int, val: dict):
        self.name = name
        if not idx:
            if self.register == "x29":
                idx = -2
            elif self.register == "x30":
                idx = -1
            elif self.register == "x19":
                idx = -3
            elif self.register == "x20":
                idx = -4
            else:
                assert idx, "Must provide offset for gadget"
        self.idx = idx
        self.val = val


class Gadget:
    def __init__(self, d: dict, nxt=None):
        self.addr = d["addr"]
        self.offset = d["offset"]
        self.registers = list()
        if "regs" in d:
            # assert that all the registers required to be set for nxt
            # are updated in this stack frame
            if nxt is not None and "vals" in nxt:
                for k1, v1 in nxt["vals"].items():
                    assert k1 in d["regs"], "required value {} not set in stack frame".format(k1)
            for k, v in d["regs"].items():
                assert -v*8 <= self.offset, "Offset for register outside stack frame"
                if nxt is not None:
                    val = None
                    if k == "x30":
                        val = nxt["addr"]
                    elif "vals" in nxt and k in nxt["vals"]:
                        val = nxt["vals"][k]
                    self.registers.append(Register(k, v, val))

    def generate(self) -> bytes:
        b = b"\x00" * self.offset
        for r in self.registers:
            if r.val is not None:
                off = self.offset + (r.idx * 8)
                b = b[:off] + r.val.to_bytes(8, "little") + b[off+8:]
        return b
