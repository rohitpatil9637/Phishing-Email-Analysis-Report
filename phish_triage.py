#!/usr/bin/env python3
"""
phish_triage.py - first-look triage of a suspicious .eml file.
Read-only: it parses the file and NEVER opens links or attachments.

"""
import csv
import email
import hashlib
import re
import sys
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser

RISKY = (".html", ".htm", ".zip", ".rar", ".7z", ".iso", ".img", ".lnk", ".js",
         ".vbs", ".docm", ".xlsm", ".exe", ".scr", ".jar", ".one", ".svg")


class Parts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.images, self.text = [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "img" and a.get("src"):
            self.images.append(a["src"])

    def handle_data(self, data):
        self.text.append(data.strip())


def defang(u):
    return u.replace("http", "hxxp").replace(".", "[.]")


def domain(addr):
    return parseaddr(addr)[1].split("@")[-1].lower()


def main(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    iocs = []

    print("=== HEADERS ===")
    for h in ("From", "Reply-To", "Return-Path", "To", "Subject", "Date"):
        print(f"{h:12}: {msg.get(h, '-')}")
    d_from, d_reply, d_ret = (domain(msg.get(h, "")) for h in
                              ("From", "Reply-To", "Return-Path"))
    if d_reply and d_reply != d_from:
        print(f"[!] Reply-To domain ({d_reply}) differs from From ({d_from})")
    if d_ret and d_ret != d_from:
        print(f"[!] Return-Path domain ({d_ret}) differs from From ({d_from})")

    print("\n=== AUTHENTICATION ===")
    auth = " ".join(msg.get_all("Authentication-Results", []))
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{k}=(\w+)", auth, re.I)
        res = m.group(1).lower() if m else "not found"
        print(f"{k.upper():6}: {res}" + ("   [!]" if res not in ("pass",) else ""))

    print("\n=== RECEIVED CHAIN (oldest first) ===")
    for r in reversed(msg.get_all("Received", [])):
        ips = re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(r))
        if ips:
            print("  hop IP:", ", ".join(ips))
            iocs += [("ip", ip) for ip in ips]

    links, images, visible = [], [], ""
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            p = Parts()
            p.feed(part.get_content())
            links += p.links
            images += p.images
            visible += " ".join(t for t in p.text if t)
        elif part.get_content_type() == "text/plain":
            links += re.findall(r"https?://[^\s\"'<>]+", part.get_content())

    print("\n=== LINKS (defanged) ===")
    for u in sorted(set(links)):
        print("  ", defang(u))
        iocs.append(("url", defang(u)))
    print(f"\nImages in body: {len(images)} | visible text length: {len(visible)}")
    if images and len(visible) < 80:
        print("[!] Image-heavy email: run OCR / QR decode on the images (Part 5)")

    print("\n=== ATTACHMENTS ===")
    for a in msg.iter_attachments():
        name = a.get_filename() or "(no name)"
        data = a.get_payload(decode=True) or b""
        sha = hashlib.sha256(data).hexdigest()
        flag = "  [!] risky type" if name.lower().endswith(RISKY) else ""
        print(f"  {name} | {a.get_content_type()} | {len(data)} bytes{flag}")
        print(f"    sha256: {sha}")
        iocs.append(("sha256", sha))
    if not list(msg.iter_attachments()):
        print("  none")

    out = path.rsplit(".", 1)[0] + "_iocs.csv"
    with open(out, "w", newline="") as f:
        csv.writer(f).writerows([("type", "value")] + iocs)
    print(f"\n[+] IOCs saved to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: phish_triage.py sample.eml")
    main(sys.argv[1])
