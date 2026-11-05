"""
mytrack_reader.py
MYTRACK card reader helper for the ACR122U.

Run it on the kiosk PC (start-reader.bat), then open the kiosk page in Chrome/Edge on the same PC.
The page talks to this program on ws://127.0.0.1:47123:
  this program → page   {"type":"reader","connected":true,"name":"ACS ACR122U PICC Interface 0"}
                        {"type":"card","uid":"E2864A4A","payload":"MT1...."|null}
                        {"type":"waiting","id":7}   the card was lifted too early: put it back to finish
                        {"type":"written","id":7,"ok":true|false,"error":"..."}
  page → this program   {"type":"write","id":7,"uid":"E2864A4A","payload":"MT1...."}

Only this computer can connect (127.0.0.1). Needs:  pip install pyscard
"""
import asyncio
import base64
import hashlib
import json
import queue
import struct
import sys
import threading
import time

from cardlib import Card, CardError

PORT = 47123
POLL_SECONDS = 0.15
# The server answers a tap in 1-3 s, and people often lift the card before that.
# A write that finds no card waits this long for the SAME card to be put back, then finishes the tap.
WRITE_WAIT_SECONDS = 10

# Only the kiosk page may use the reader. Any other website open in this PC's browser could
# otherwise connect to ws://127.0.0.1:47123 and write on the cards.
# Put your site's address in allowed-origins.txt (next to this file), one per line, e.g.
#   https://ojt.your-domain.example
DEV_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}


def load_origins():
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowed-origins.txt")
    extra = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip().rstrip("/")
                if line and not line.startswith("#"):
                    extra.add(line.lower())
    except FileNotFoundError:
        pass
    return DEV_ORIGINS | extra


ALLOWED_ORIGINS = load_origins()

try:
    from smartcard.System import readers as list_readers
    from smartcard.Exceptions import CardConnectionException, NoCardException
except ImportError:  # pragma: no cover
    print("pyscard is missing. Run:  pip install pyscard")
    sys.exit(1)

# ACR122U buzzer (ACS API: pseudo-APDUs to the reader itself)
APDU_DETECT_BEEP_OFF = [0xFF, 0x00, 0x52, 0x00, 0x00]          # don't beep when a card is first seen
# FF 00 40 <LED: 00 = unchanged> 04 <T1> <T2> <repeat> <buzzer during T1>   (T1/T2 in 100 ms)
APDU_BEEP_OK = [0xFF, 0x00, 0x40, 0x00, 0x04, 0x02, 0x00, 0x01, 0x01]     # one 0.2 s beep
APDU_BEEP_ERROR = [0xFF, 0x00, 0x40, 0x00, 0x04, 0x01, 0x01, 0x02, 0x01]  # two short beeps


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def uid_forms(raw):
    """Every way the same card UID can be written: hex (E2864A4A), hex with the bytes reversed,
    and the decimal number the old USB reader types (e.g. 1246398178). Cards registered with the
    old USB reader keep their decimal UID in the database, so the page may send that form back."""
    s = "".join(ch for ch in str(raw or "") if ch.isalnum()).upper()
    out = {s}
    hexes = []
    if s and all(c in "0123456789ABCDEF" for c in s) and len(s) % 2 == 0:
        hexes.append(s)
    if s.isdigit():
        n = int(s)
        h = format(n, "X")
        for size in (8, 14, 20):
            if len(h) <= size:
                hexes.append(h.zfill(size))
                break
    for h in hexes:
        rev = "".join(reversed([h[i:i + 2] for i in range(0, len(h), 2)]))
        out.update({h, rev, str(int(h, 16)), str(int(rev, 16))})
    out.discard("")
    return out


def same_card(a, b):
    return bool(uid_forms(a) & uid_forms(b))


# ───────────────────────── the reader (one thread does all the card work) ─────────────────────────

class ReaderThread(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit                     # emit(dict) → sent to every connected page
        self.jobs = queue.Queue()            # write jobs from the page
        self.conn = None                     # connection to the card on the reader now
        self.card = None
        self.uid = None
        self.reader_name = None
        self.pending = None                  # a write waiting for its card to come back: (job, deadline)

    def run(self):
        while True:
            try:
                self.tick()
            except Exception as e:           # never die: unplugging the reader must not stop the helper
                log("reader error:", e)
                self.drop_card()
                time.sleep(1)
            time.sleep(POLL_SECONDS)

    def pick_reader(self):
        rs = list_readers()
        # the ACR122U's own name, else the first contactless reader found
        r = next((x for x in rs if "ACR122" in str(x)), None) or next((x for x in rs if "PICC" in str(x)), None) or (rs[0] if rs else None)
        name = str(r) if r else None
        if name != self.reader_name:
            self.reader_name = name
            self.quiet = False               # a re-plugged reader beeps on detection again: turn it off again
            log("reader:", name or "none plugged in")
            self.emit({"type": "reader", "connected": bool(r), "name": name})
        return r

    def drop_card(self):
        if self.conn:
            try:
                self.conn.disconnect()
            except Exception:
                pass
        self.conn = self.card = self.uid = None

    def tick(self):
        # a write the page asked for (the card is still on the reader)
        try:
            job = self.jobs.get_nowait()
        except queue.Empty:
            job = None
        if job:
            if job.get("type") == "beep":
                self.do_beep(job)
            else:
                self.do_write(job)
            return

        if self.pending and time.time() > self.pending[1]:
            job, _ = self.pending
            self.pending = None
            log("write failed: the card was not put back in time")
            self.emit({"type": "written", "id": job.get("id"), "ok": False, "error": "The card was taken away too early"})

        r = self.pick_reader()
        if not r:
            self.drop_card()
            return
        if self.conn:
            # is the same card still there?
            try:
                self.card.uid()
            except Exception:
                log("card removed")
                self.drop_card()
            return
        try:
            conn = r.createConnection()
            conn.connect()
        except (NoCardException, CardConnectionException):
            return
        except Exception:
            return
        self.conn = conn
        # the reader beeps by itself when it sees a card; turn that off so the only beep means "done"
        # (the setting stays until the reader is unplugged; the very first card after plugging in still beeps once)
        if not getattr(self, "quiet", False):
            try:
                conn.transmit(APDU_DETECT_BEEP_OFF)
                self.quiet = True
            except Exception:
                pass
        self.card = Card(lambda apdu: conn.transmit(apdu), bytes(conn.getATR()))
        try:
            self.uid = self.card.uid()
            if self.pending and same_card(self.pending[0].get("uid"), self.uid):
                # the card of the tap that is still finishing came back: write its new code now
                job, _ = self.pending
                self.pending = None
                self.do_write(job)
                return
            payload = self.card.read_payload()
            log("card", self.uid, self.card.kind, "code: yes" if payload else "code: none")
            self.emit({"type": "card", "uid": self.uid, "payload": payload})
        except CardError as e:
            log("couldn't read the card:", e)
            self.emit({"type": "card", "uid": self.uid, "error": str(e)})

    def do_beep(self, job):
        apdu = APDU_BEEP_OK if job.get("kind") == "ok" else APDU_BEEP_ERROR
        if self.conn:                        # the card is still on the reader: the usual case
            try:
                self.conn.transmit(apdu)
                return
            except Exception:
                pass
        # card already taken away: talk to the reader itself (direct mode, no card needed)
        try:
            from smartcard import scard as S
            r = self.pick_reader()
            if not r:
                return
            hr, ctx = S.SCardEstablishContext(S.SCARD_SCOPE_USER)
            if hr != S.SCARD_S_SUCCESS:
                raise RuntimeError(S.SCardGetErrorMessage(hr))
            try:
                hr, card, _proto = S.SCardConnect(ctx, str(r), S.SCARD_SHARE_DIRECT, 0)
                if hr != S.SCARD_S_SUCCESS:
                    raise RuntimeError(S.SCardGetErrorMessage(hr))
                try:
                    # 3500 = the ACS "escape" code; on Windows the reader answers it in direct mode
                    hr, _resp = S.SCardControl(card, S.SCARD_CTL_CODE(3500), apdu)
                    if hr != S.SCARD_S_SUCCESS:
                        raise RuntimeError(S.SCardGetErrorMessage(hr))
                finally:
                    S.SCardDisconnect(card, S.SCARD_LEAVE_CARD)
            finally:
                S.SCardReleaseContext(ctx)
        except Exception as e:
            log("beep skipped (no card on the reader):", e)

    def do_write(self, job):
        jid = job.get("id")
        if not self.card or (job.get("uid") and not same_card(job["uid"], self.uid)):
            # the card was lifted before the server answered: wait for it to be put back
            self.pending = (job, time.time() + WRITE_WAIT_SECONDS)
            log("waiting for card", job.get("uid") or "", "to be put back to write its new code")
            self.emit({"type": "waiting", "id": jid})
            return
        try:
            self.card.write_payload(job["payload"])
            log("card", self.uid, "new code written")
            self.emit({"type": "written", "id": jid, "ok": True})
        except Exception as e:
            if not job.get("retried"):
                # usually the card was lifted in the middle of the write: try once more when it is put back
                job["retried"] = True
                self.drop_card()
                self.pending = (job, time.time() + WRITE_WAIT_SECONDS)
                log("write interrupted (", e, "), waiting for the card to be put back")
                self.emit({"type": "waiting", "id": jid})
                return
            log("write failed:", e)
            self.emit({"type": "written", "id": jid, "ok": False, "error": str(e)})


# ───────────────────────── a tiny WebSocket server (no extra packages) ─────────────────────────

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Hub:
    def __init__(self):
        self.clients = set()
        self.loop = None
        self.reader = None
        self.last_reader = None

    def emit(self, msg):                     # called from the reader thread
        if msg.get("type") == "reader":
            self.last_reader = msg
        if self.loop:
            asyncio.run_coroutine_threadsafe(self.broadcast(msg), self.loop)

    async def broadcast(self, msg):
        data = frame(json.dumps(msg))
        for w in list(self.clients):
            try:
                w.write(data)
                await w.drain()
            except Exception:
                self.clients.discard(w)


def frame(text: str) -> bytes:
    b = text.encode("utf-8")
    if len(b) < 126:
        head = struct.pack("!BB", 0x81, len(b))
    elif len(b) < 65536:
        head = struct.pack("!BBH", 0x81, 126, len(b))
    else:
        head = struct.pack("!BBQ", 0x81, 127, len(b))
    return head + b


async def read_frame(r):
    b1, b2 = await r.readexactly(2)
    op, masked, n = b1 & 0x0F, b2 & 0x80, b2 & 0x7F
    if n == 126:
        n = struct.unpack("!H", await r.readexactly(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", await r.readexactly(8))[0]
    mask = await r.readexactly(4) if masked else b"\0\0\0\0"
    data = bytearray(await r.readexactly(n))
    for i in range(n):
        data[i] ^= mask[i % 4]
    return op, bytes(data)


async def handle(hub, r, w):
    try:
        req = await r.readuntil(b"\r\n\r\n")
        headers = {}
        for line in req.decode("latin-1").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        key = headers.get("sec-websocket-key")
        origin = headers.get("origin", "").rstrip("/").lower()
        if key and origin and origin not in ALLOWED_ORIGINS:
            log("refused a page from", origin, "(add it to allowed-origins.txt if it is your kiosk)")
            w.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await w.drain()
            w.close()
            return
        if not key:
            w.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nMYTRACK reader helper is running.\n")
            await w.drain()
            w.close()
            return
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        w.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        await w.drain()
        hub.clients.add(w)
        log("kiosk page connected")
        if hub.last_reader:
            w.write(frame(json.dumps(hub.last_reader)))
            await w.drain()
        while True:
            op, data = await read_frame(r)
            if op == 0x8:                    # close
                break
            if op == 0x9:                    # ping → pong
                w.write(bytes([0x8A, len(data)]) + data)
                await w.drain()
                continue
            if op != 0x1:
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except ValueError:
                continue
            if msg.get("type") == "write" and isinstance(msg.get("payload"), str):
                hub.reader.jobs.put(msg)
            elif msg.get("type") == "beep":
                hub.reader.jobs.put({"type": "beep", "kind": "ok" if msg.get("kind") == "ok" else "error"})
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        hub.clients.discard(w)
        try:
            w.close()
        except Exception:
            pass


async def main():
    hub = Hub()
    hub.loop = asyncio.get_running_loop()
    hub.reader = ReaderThread(hub.emit)
    hub.reader.start()
    server = await asyncio.start_server(lambda r, w: handle(hub, r, w), "127.0.0.1", PORT)
    log(f"Card reader helper running on ws://127.0.0.1:{PORT}  (keep this window open)")
    log("kiosk pages allowed:", ", ".join(sorted(ALLOWED_ORIGINS)))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass