"""
cardlib.py: read and write MYTRACK's one-time code on NFC cards through an ACR122U (PC/SC).

Works with:
  * MIFARE Classic 1K / 4K  (the current CSU cards: "NXP - Mifare Classic 1k")
  * NTAG213 / 215 / 216 and MIFARE Ultralight

The code is stored the standard way (NDEF), as one record of type "application/x-mytrack",
so the Android phone kiosk (Chrome Web NFC) and the ACR122U read and write the very same thing.
A blank MIFARE Classic card is formatted for NDEF the same way Android does it.

Everything here only needs a `transmit(apdu_bytes) -> (data_bytes, sw1, sw2)` function,
so it can be tested without a reader (see test_cardlib.py).
"""

MIME = b"application/x-mytrack"

KEY_DEFAULT = bytes.fromhex("FFFFFFFFFFFF")     # blank card
KEY_NDEF = bytes.fromhex("D3F7D3F7D3F7")        # NFC Forum public key for NDEF sectors
KEY_MAD = bytes.fromhex("A0A1A2A3A4A5")         # MAD (sector 0) public key

# sector trailers exactly as Android / NXP write them when formatting a card for NDEF
TRAILER_MAD = KEY_MAD + bytes.fromhex("787788C1") + KEY_DEFAULT
TRAILER_NDEF = KEY_NDEF + bytes.fromhex("7F078840") + KEY_DEFAULT


class CardError(Exception):
    pass


# ───────────────────────── NDEF ─────────────────────────

def ndef_record(payload: str) -> bytes:
    """one short MIME record (MB|ME|SR, TNF=2) holding the MYTRACK code"""
    data = payload.encode("ascii")
    if len(data) > 255:
        raise CardError("payload too long")
    return bytes([0xD2, len(MIME), len(data)]) + MIME + data


def ndef_tlv(message: bytes) -> bytes:
    if len(message) < 0xFF:
        head = bytes([0x03, len(message)])
    else:
        head = bytes([0x03, 0xFF, len(message) >> 8, len(message) & 0xFF])
    return head + message + b"\xFE"


def parse_tlv(data: bytes):
    """returns the NDEF message bytes from a TLV area, or None. Raises IndexError if data is too short."""
    i = 0
    while i < len(data):
        t = data[i]
        if t == 0x00:            # NULL TLV
            i += 1
            continue
        if t == 0xFE:            # terminator: no NDEF
            return None
        n = data[i + 1]
        if n == 0xFF:
            n = (data[i + 2] << 8) | data[i + 3]
            start = i + 4
        else:
            start = i + 2
        if t == 0x03:
            if start + n > len(data):
                raise IndexError("need more data")
            return bytes(data[start:start + n])
        i = start + n            # skip other TLVs (lock / memory control)
    raise IndexError("need more data")


def find_payload(message: bytes):
    """the MYTRACK code in an NDEF message, or None"""
    i = 0
    while i < len(message):
        h = message[i]
        tnf, sr, il = h & 0x07, h & 0x10, h & 0x08
        tlen = message[i + 1]
        if sr:
            plen = message[i + 2]
            j = i + 3
        else:
            plen = int.from_bytes(message[i + 2:i + 6], "big")
            j = i + 6
        idlen = message[j] if il else 0
        j += 1 if il else 0
        rtype = message[j:j + tlen]
        j += tlen + idlen
        payload = message[j:j + plen]
        if tnf == 0x02 and rtype == MIME:
            try:
                return payload.decode("ascii").strip()
            except UnicodeDecodeError:
                return None
        if h & 0x40:             # ME: last record
            break
        i = j + plen
    return None


# ───────────────────────── MAD (sector 0 of a MIFARE Classic NDEF card) ─────────────────────────

def mad_crc(data: bytes) -> int:
    """CRC-8 of the MAD (NXP AN10787): polynomial 0x1D, preset 0xC7"""
    crc = 0xC7
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def mad_blocks(ndef_sectors: int = 15) -> bytes:
    """blocks 1 and 2 of sector 0: sectors 1..ndef_sectors are NDEF (AID 0xE103)"""
    aids = b"".join((b"\x03\xE1" if s <= ndef_sectors else b"\x00\x00") for s in range(1, 16))
    body = bytes([0x01]) + aids               # info byte + 15 AIDs = 31 bytes
    return bytes([mad_crc(body)]) + body      # 32 bytes


# ───────────────────────── the card ─────────────────────────

class Card:
    def __init__(self, transmit, atr: bytes = b""):
        self._tx = transmit
        self.atr = bytes(atr)
        self.kind = self._kind()

    # PC/SC pseudo-APDUs of the ACR122U
    def apdu(self, cmd: bytes) -> bytes:
        data, sw1, sw2 = self._tx(list(cmd))
        if (sw1, sw2) != (0x90, 0x00):
            raise CardError(f"APDU {bytes(cmd[:5]).hex()} failed: {sw1:02X}{sw2:02X}")
        return bytes(data)

    def _kind(self) -> str:
        # PC/SC part 3 ATR: bytes 13-14 = card name (0001 Classic 1K, 0002 Classic 4K, 0003 Ultralight/NTAG)
        name = self.atr[13:15] if len(self.atr) >= 15 else b""
        if name == b"\x00\x01":
            return "classic1k"
        if name == b"\x00\x02":
            return "classic4k"
        if name == b"\x00\x03":
            return "ultralight"
        return "unknown"

    def uid(self) -> str:
        return self.apdu(bytes.fromhex("FFCA000000")).hex().upper()

    # ── MIFARE Classic ──
    def _load_key(self, key: bytes):
        self.apdu(bytes.fromhex("FF82000006") + key)

    def _auth(self, block: int, key: bytes, key_type: int = 0x60) -> bool:
        try:
            self._load_key(key)
            self.apdu(bytes([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type, 0x00]))
            return True
        except CardError:
            return False

    def _read(self, block: int) -> bytes:
        return self.apdu(bytes([0xFF, 0xB0, 0x00, block, 0x10]))

    def _write(self, block: int, data: bytes):
        assert len(data) == 16
        self.apdu(bytes([0xFF, 0xD6, 0x00, block, 0x10]) + data)

    def _sectors(self):
        n = 40 if self.kind == "classic4k" else 16
        for s in range(1, n):
            if s == 16:          # 4K: sector 16 is the second MAD
                continue
            first = s * 4 if s < 32 else 128 + (s - 32) * 16
            count = 3 if s < 32 else 15
            yield s, first, count

    def _classic_read_ndef(self):
        area = b""
        for s, first, count in self._sectors():
            if not self._auth(first, KEY_NDEF):
                if s == 1:
                    return None   # not formatted for NDEF (blank card)
                break
            for b in range(first, first + count):
                area += self._read(b)
            try:
                msg = parse_tlv(area)
                return find_payload(msg) if msg else None
            except IndexError:
                continue
        return None

    def _classic_format(self):
        """blank card → NDEF card (same layout as Android): MAD in sector 0, public key on sectors 1-15"""
        if not self._auth(3, KEY_DEFAULT):
            raise CardError("This card is locked with unknown keys and can't be used")
        mad = mad_blocks(15)
        self._write(1, mad[:16])
        self._write(2, mad[16:])
        self._write(3, TRAILER_MAD)
        for s in range(1, 16):
            first = s * 4
            if not self._auth(first, KEY_DEFAULT):
                raise CardError(f"Sector {s} is locked with unknown keys")
            self._write(first, b"\x03\x00\xFE" + bytes(13) if s == 1 else bytes(16))
            self._write(first + 1, bytes(16))
            self._write(first + 2, bytes(16))
            self._write(first + 3, TRAILER_NDEF)

    def _classic_write_ndef(self, payload: str):
        if not self._auth(4, KEY_NDEF):
            self._classic_format()
        data = ndef_tlv(ndef_record(payload))
        data += bytes((-len(data)) % 16)
        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        for s, first, count in self._sectors():
            if not blocks:
                break
            if not self._auth(first, KEY_NDEF):
                raise CardError("Couldn't open the card to write")
            for b in range(first, first + count):
                if not blocks:
                    break
                self._write(b, blocks.pop(0))
        if blocks:
            raise CardError("The card is too small")

    # ── NTAG / Ultralight (4-byte pages; a READ returns 4 pages) ──
    def _ul_read_ndef(self):
        cc = self.apdu(bytes([0xFF, 0xB0, 0x00, 0x03, 0x10]))[:4]
        if cc[0] != 0xE1:
            return None
        area = b""
        page = 4
        end = 4 + cc[2] * 2          # data area: CC byte 2 = size / 8 bytes = 2 pages each
        while page < end:
            area += self.apdu(bytes([0xFF, 0xB0, 0x00, page, 0x10]))
            page += 4
            try:
                msg = parse_tlv(area)
                return find_payload(msg) if msg else None
            except IndexError:
                continue
        return None

    def _ul_write_ndef(self, payload: str):
        cc = self.apdu(bytes([0xFF, 0xB0, 0x00, 0x03, 0x10]))[:4]
        if cc[0] != 0xE1:
            raise CardError("This tag is not formatted for NDEF")
        data = ndef_tlv(ndef_record(payload))
        data += bytes((-len(data)) % 4)
        if len(data) > cc[2] * 8:
            raise CardError("The tag is too small")
        for i in range(0, len(data), 4):
            self.apdu(bytes([0xFF, 0xD6, 0x00, 4 + i // 4, 0x04]) + data[i:i + 4])

    # ── public ──
    def _is_classic(self) -> bool:
        if self.kind != "unknown":
            return self.kind.startswith("classic")
        return len(self.uid()) == 8      # 4-byte UID: MIFARE Classic; 7-byte UID: NTAG / Ultralight

    def read_payload(self):
        """the MYTRACK code on the card, or None"""
        return self._classic_read_ndef() if self._is_classic() else self._ul_read_ndef()

    def write_payload(self, payload: str):
        """writes the code, then reads it back to be sure"""
        if self._is_classic():
            self._classic_write_ndef(payload)
        else:
            self._ul_write_ndef(payload)
        if self.read_payload() != payload:
            raise CardError("The card didn't keep the new code")