"""Tests cardlib against simulated cards (no reader needed):  python test_cardlib.py"""
import cardlib as C

ATR_1K = bytes.fromhex("3B8F8001804F0CA000000306030001000000006A")
ATR_UL = bytes.fromhex("3B8F8001804F0CA0000003060300030000000068")


class FakeClassic:
    """MIFARE Classic 1K behind an ACR122U, with real key / access-bit rules for the layouts used here"""
    def __init__(self, uid="E2864A4A"):
        self.uid = bytes.fromhex(uid)
        self.blocks = [bytes(16) for _ in range(64)]
        self.blocks[0] = self.uid + bytes(12)
        for s in range(16):
            self.blocks[s * 4 + 3] = C.KEY_DEFAULT + bytes.fromhex("FF078069") + C.KEY_DEFAULT   # transport
        self.key = None
        self.authed = None   # (sector, key_type)

    def access(self, sector):
        return self.blocks[sector * 4 + 3][6:9].hex().upper()

    def allowed(self, block, op):
        sec, kt = block // 4, self.authed[1]
        if self.authed is None or self.authed[0] != sec:
            return False
        acc, trailer = self.access(sec), block % 4 == 3
        if acc == "FF0780":                       # transport: key A does everything
            return kt == 0x60 or not trailer
        if acc == "7F0788":                       # NDEF sector: data r/w with A or B; trailer write with B
            return (not trailer) or kt == 0x61
        if acc == "787788":                       # MAD: read A|B, write B
            return op == "r" or kt == 0x61
        return False

    def __call__(self, apdu):
        a = bytes(apdu)
        if a[:2] == b"\xFF\xCA":
            return list(self.uid), 0x90, 0x00
        if a[:2] == b"\xFF\x82":
            self.key = a[5:11]; return [], 0x90, 0x00
        if a[:2] == b"\xFF\x86":
            block, kt = a[7], a[8]
            t = self.blocks[(block // 4) * 4 + 3]
            real = t[:6] if kt == 0x60 else t[10:16]
            if self.key == real:
                self.authed = (block // 4, kt); return [], 0x90, 0x00
            self.authed = None; return [], 0x63, 0x00
        if a[:2] == b"\xFF\xB0":
            b = a[3]
            if self.authed is None or not self.allowed(b, "r"): return [], 0x63, 0x00
            return list(self.blocks[b]), 0x90, 0x00
        if a[:2] == b"\xFF\xD6":
            b = a[3]
            if b == 0 or self.authed is None or not self.allowed(b, "w"): return [], 0x63, 0x00
            self.blocks[b] = a[5:21]; return [], 0x90, 0x00
        return [], 0x6A, 0x81


class FakeNtag:
    def __init__(self):
        self.uid = bytes.fromhex("04A1B2C3D4E5F6")
        self.pages = [bytes(4) for _ in range(135)]
        self.pages[3] = bytes.fromhex("E1103E00")         # NTAG215 capability container
        self.pages[4] = bytes.fromhex("0300FE00")

    def __call__(self, apdu):
        a = bytes(apdu)
        if a[:2] == b"\xFF\xCA": return list(self.uid), 0x90, 0x00
        if a[:2] == b"\xFF\xB0":
            p = a[3]; return list(b"".join(self.pages[p:p + 4])), 0x90, 0x00
        if a[:2] == b"\xFF\xD6":
            self.pages[a[3]] = a[5:9]; return [], 0x90, 0x00
        return [], 0x6A, 0x81


def test():
    # the MAD checksum of an Android-formatted card is 0x14 ("14 01 03 E1 03 E1 ...")
    assert C.mad_blocks(15)[:4] == bytes.fromhex("140103E1"), C.mad_blocks(15)[:4].hex()

    p1 = "MT1.PyUE4E-JQdOaDAMF6CwzAQ.oS1REj6vxcHNQY8VTU9n7w"
    p2 = "MT1.PyUE4E-JQdOaDAMF6CwzAQ.zzzzzzzzzzzzzzzzzzzzzz"

    fake = FakeClassic()
    card = C.Card(fake, ATR_1K)
    assert card.kind == "classic1k" and card.uid() == "E2864A4A"
    assert card.read_payload() is None                  # blank card
    card.write_payload(p1)                              # formats it, then writes
    assert card.read_payload() == p1
    assert fake.access(0) == "787788" and fake.access(1) == "7F0788" and fake.access(15) == "7F0788"
    card.write_payload(p2)                              # next tap: new code
    assert card.read_payload() == p2
    assert C.Card(fake, b"").read_payload() == p2       # unknown ATR: decided by the UID length

    nt = FakeNtag()
    card = C.Card(nt, ATR_UL)
    assert card.read_payload() is None
    card.write_payload(p1)
    assert card.read_payload() == p1
    card.write_payload(p2)
    assert card.read_payload() == p2

    # an NDEF message as Chrome on Android writes it is understood
    msg = C.ndef_record(p1)
    assert C.find_payload(msg) == p1
    print("all card tests passed")


if __name__ == "__main__":
    test()