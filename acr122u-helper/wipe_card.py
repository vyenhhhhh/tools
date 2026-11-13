"""
MYTRACK - clear the one-time code on a card (for testing only)

Use this when a card was used with ANOTHER database (for example your real Supabase
project) and is now tapped on the test system. The test system does not know the
card ID written on it, so it reports the card as suspicious. Clearing the code makes
the card "new" again: its next tap on the kiosk is accepted and gives it a fresh code.

Do the same again when you switch back to the real database after testing.

Close start-reader.bat first (only one program can use the ACR122U at a time).

  python wipe_card.py        then put the card on the reader
"""
import sys
import time

from smartcard.System import readers

from cardlib import Card, CardError

CLEARED = "MT0.cleared"   # not a MYTRACK code, so the server treats the card as new


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
    card = wait_for_card()
    uid = card.uid()
    before = card.read_payload()
    if not before or not before.startswith("MT1."):
        print(f"Card {uid} has no MYTRACK code. Nothing to clear.")
        return
    try:
        card.write_payload(CLEARED)
    except CardError as e:
        sys.exit(f"Could not clear the card: {e}")
    print(f"Cleared card {uid}. Start start-reader.bat again and tap it on the kiosk.")


if __name__ == "__main__":
    main()