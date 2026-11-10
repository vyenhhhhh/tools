"""
MYTRACK - copied-card test (for testing and the defense only)

Makes a "copied card" on purpose, so you can see the system catch it and show
the alert on the administrator's dashboard.

Close start-reader.bat first (only one program can use the ACR122U at a time).

  python copy_test.py save      put the REAL card on the reader: saves its code to saved_code.txt
  python copy_test.py write     put ANOTHER card on the reader: writes the saved code onto it

Test 1, copied to another card (alert reason "copied to other card"):
  1. save with the intern's real card, 2. write onto a second blank card,
  3. start start-reader.bat again and tap the SECOND card on the kiosk.

Test 2, old code (alert reason "old code"):
  1. save with the intern's real card, 2. tap the real card on the kiosk once (it gets a new code),
  3. close the helper, write the saved (now old) code back onto the real card,
  4. start the helper again and tap the real card.

After the test, open Admin > NFC Cards > Card alerts, resolve the alert with
"Reset card", then tap the real card once so it gets a fresh code.
"""
import sys
import time

from smartcard.System import readers

from cardlib import Card, CardError

SAVE_FILE = "saved_code.txt"


def wait_for_card():
    rs = [r for r in readers() if "ACR122" in str(r) or "PICC" in str(r)] or readers()
    if not rs:
        sys.exit("No reader found. Plug in the ACR122U.")
    print("Put the card on the reader...")
    while True:
        try:
            conn = rs[0].createConnection()
            conn.connect()
            return Card(lambda apdu: conn.transmit(apdu), bytes(conn.getATR()))
        except Exception:
            time.sleep(0.3)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("save", "write"):
        sys.exit(__doc__)
    card = wait_for_card()
    uid = card.uid()
    if sys.argv[1] == "save":
        code = card.read_payload()
        if not code:
            sys.exit(f"Card {uid} has no MYTRACK code yet. Tap it on the kiosk once first.")
        with open(SAVE_FILE, "w", encoding="utf-8") as f:
            f.write(code)
        print(f"Saved the code of card {uid} to {SAVE_FILE}.")
    else:
        try:
            with open(SAVE_FILE, encoding="utf-8") as f:
                code = f.read().strip()
        except FileNotFoundError:
            sys.exit("Nothing saved yet. Run: python copy_test.py save")
        try:
            card.write_payload(code)
        except CardError as e:
            sys.exit(f"Could not write: {e}")
        print(f"Wrote the saved code onto card {uid}. Now tap it on the kiosk.")


if __name__ == "__main__":
    main()