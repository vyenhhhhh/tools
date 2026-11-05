MYTRACK - ACR122U card reader helper
=====================================

What it does
  The kiosk page can't talk to the ACR122U by itself, so this small program does it.
  It reads the card (UID + MYTRACK's one-time code) and writes the new code after every tap.
  It only accepts connections from the same computer (ws://127.0.0.1:47123).

Set up the kiosk PC (once)
  1. Install the ACR122U driver: "ACS Unified PC/SC Driver" from https://www.acs.com.hk (Downloads, ACR122U).
     Plug the reader in. Windows should list it as "ACS ACR122U PICC Interface".
  2. Install Python 3 from https://www.python.org/downloads/  (tick "Add python.exe to PATH").
  3. Copy this folder to the kiosk PC.

Every day
  1. Double-click start-reader.bat (the first time it installs "pyscard"). Keep the window open.
  2. Open the kiosk page in Chrome or Edge. The top bar shows "ACR122U ready".
     If it shows another reader, open the page once with  ?reader=acr122u  at the end of the address.

Cards
  - MIFARE Classic 1K (your current cards) and NTAG213/215/216 both work.
  - A blank MIFARE Classic card is formatted for NDEF on its first tap (same layout as an Android phone uses),
    so the phone kiosk and the ACR122U kiosk read the same card. The UID does not change, so the old USB
    reader still recognises the card.

Check without a reader
  python test_cardlib.py      (tests reading/writing on simulated cards)

Troubleshooting
  - "no reader plugged in": re-plug the reader, check the ACS driver is installed.
  - Windows shows "installing device driver software" every time a card is placed: run gpedit.msc →
    Computer Configuration → Administrative Templates → Windows Components → Smart Card →
    "Turn on Smart Card Plug and Play service" = Disabled.

AFTER DEPLOYING (the kiosk page is on your real website)
  Open allowed-origins.txt and add your website's address on its own line, for example
      https://ojt.your-domain.example
  (no / at the end). Then close and reopen start-reader.bat.
  The helper only talks to these pages, so another website open in the browser can't write on the cards.
  If the kiosk says "ACR122U helper not running" but the black window is open, check that window:
  it says "refused a page from ..." when the address is missing from allowed-origins.txt.