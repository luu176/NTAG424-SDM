# NTAG424 SDM Writer

This repo simplifies writing Secure Dynamic Messaging (SDM) payloads to **NTAG424** NFC tags using a USB NFC reader (such as the **ACR122U**). Whether you’re building secure business cards, dynamic access links, or just want a more private way to share your profile—this script handles the hard part.

## What It Does

* **Option 1:**
  Generates an **NDEF payload** containing an **encrypted UID + counter (PICCDATA)** and a **CMAC**, ensuring each URL read from the tag is unique and secured.

* **Option 2:**
  Generates an **NDEF payload** with **unencrypted UID + counter + CMAC** inside the URL — less secure, but easier to debug and integrate.

> **Important:** This script only prepares the NTAG424 tags. You’ll need to handle your website/backend/VPS separately to process and validate incoming dynamic URLs.

---

## Features

* Supports USB NFC readers like **ACR122U**.
* Handles **key management**, **SDM payload generation**, and **NDEF writing** automatically.
* Designed for simple sharing of personal links, profiles, or business pages — without exposing static URLs or permanent identifiers.
* No need to read through complex datasheets — this tool does all the heavy lifting for you.

---

## Getting Started

1. Keep your NTAG424 tag on the reader at all times while running the script.
2. Choose between encrypted or unencrypted SDM payload generation.
3. Flash the NDEF message directly to your tag.

---

## Datasheets / References

This project was made possible thanks to:

* [NTAG 424 DNA Secure Dynamic Messaging – Application Note (AN12196)](https://www.nxp.com/docs/en/application-note/AN12196.pdf)
* [NTAG 424 DNA Data Sheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)

---

## Why This Repo?

Because not everyone wants to spend days buried in datasheets to do something simple. This script automates the process so you can focus on what matters — sharing your links securely.

Sit back, tag on reader, run the script, and let it handle the work for you.


