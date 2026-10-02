#!/usr/bin/env python3
"""Public-site guard: fail CI when files headed for a public website carry
personal data.  Pure Python 3, no dependencies.

Usage:  python3 public_guard.py [--radius-m 250] PATH [PATH ...]
        PATH may be a file or a directory (scanned recursively).

Checks
  images (.jpg/.jpeg/.tif/.tiff/.heic/.png/.webp)  GPS EXIF block present -> FAIL
  videos (.mp4/.mov)                                 ©xyz / ISO6709 location atom -> FAIL
  text   (.html/.htm/.js/.json/.css/.txt/.md/.csv/.svg/.xml/.geojson)
         e-mail addresses, US phone numbers, SSN / card-shaped numbers,
         street addresses, private IPv4 -> FAIL
         financial / identity data: masked or full account numbers, routing
         numbers, EIN/ITIN, VINs, driver-licence / passport / DOB / Medicare
         markers, IRS-tax-form terms (1040, 1099, W-2, AGI, transcript),
         credential words (password, PIN, recovery code, API key) -> FAIL
         institution names and finance jargon (Wealthfront, Fidelity, Roth,
         401(k), net worth, policy number ...) -> WARNING (shows on the PR,
         does not block; promote a word to FAIL by moving it between lists)
         allowlist: .github/public-guard-allow.txt, one "<path-substring>  <regex>"
         per line; a finding whose "<label>: <text>" matches is ignored
         any lat/lon pair within RADIUS of a home -> FAIL
         (homes come from env PRIVACY_HOMES = "lat,lon;lat,lon"; when the
         variable is missing the proximity check is SKIPPED with a warning,
         so the secret never has to be committed)
  any file > 25 MB added, or a page > 80 MB -> FAIL (GitHub hard limit is 100 MB)

Exit status 1 on any FAIL, 0 otherwise.  Findings print as GitHub annotations
(::error file=...::) so they show inline on the PR.
"""
import math
import os
import re
import struct
import sys

IMAGE_EXT = {".jpg", ".jpeg", ".tif", ".tiff", ".heic", ".png", ".webp"}
VIDEO_EXT = {".mp4", ".mov", ".m4v"}
TEXT_EXT = {".html", ".htm", ".js", ".json", ".css", ".txt", ".md", ".csv",
            ".svg", ".xml", ".geojson", ".jsonc", ".yaml", ".yml"}
MAX_FILE_MB = 25
MAX_PAGE_MB = 80

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<![\d.])(?:\+?1[-. ])?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?![\d.])")
SSN = re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")
CARD = re.compile(r"(?<![\d-])(?:\d{4}[- ]){3}\d{4}(?![\d-])")
# "123 Main St" but not "— Ocean Dr" (the — em-dash escape ends in digits)
STREET = re.compile(r"(?<![\w\\#.])\d{1,5} (?:[A-Z][a-z]+ ){1,3}"
                    r"(?:St|Street|Ave|Avenue|Rd|Road|Dr|Drive|Ln|Lane|Blvd|Boulevard|Ct|Court|Pl|Place|Way|Ter|Terrace|Cir|Circle)\b\.?")
PRIVATE_IP = re.compile(r"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])")
# two decimals close together: "44.552, -68.66", "[41.49,-71.31]", '"la": 44.5, "lo": -68.6'
PAIR = re.compile(r"(-?\d{1,3}\.\d{2,})[^\d\-]{1,12}(-?\d{1,3}\.\d{2,})")

# --- financial / identity: FAIL ---
FIN_FAIL = [
    ("masked account number", re.compile(r"(?:\*{2,}|x{2,}|X{2,}|•{2,}|ending(?: in)?|last ?(?:4|four)\D{0,6})\s?\d{4}(?!\d)")),
    ("account number", re.compile(r"\b(?:acc(?:oun)?t|a/c)\s*(?:no|num(?:ber)?|#|id)?\W{0,3}\d{6,17}\b", re.I)),
    ("routing number", re.compile(r"\b(?:routing|aba|rtn)\b\W{0,20}\d{9}\b", re.I)),
    ("EIN", re.compile(r"\bEIN\W{0,6}\d{2}-\d{7}\b")),
    ("ITIN/SSN marker", re.compile(r"\b(?:ssn|itin|social security)\b", re.I)),
    ("tax form / IRS term", re.compile(r"(?<![\w.\-$])(?:IRS|Form 1040|1040(?:-[A-Z]+)?|1099(?:-[A-Z]+)?|W-2|W-4|K-1|AGI|MAGI|tax transcript|tax return|FreeTaxUSA)(?![\w.\-])")),
    ("VIN", re.compile(r"\b(?=[A-HJ-NPR-Z0-9]{17}\b)(?=[A-HJ-NPR-Z0-9]*\d)[A-HJ-NPR-Z0-9]*[A-HJ-NPR-Z][A-HJ-NPR-Z0-9]*\b")),
    ("confirmation/claim number", re.compile(r"\b(?:conf(?:irmation)?|claim|policy|member|group)\s*(?:no|num(?:ber)?|#|id)?\W{0,3}\d{6,}\b", re.I)),
    ("dollar amount >= $10,000", re.compile(r"\$\s?\d{1,3}(?:,\d{3}){2,}(?:\.\d{2})?|\$\s?\d{5,}(?:\.\d{2})?")),
]
# --- institution names / finance jargon / sensitive-topic words: WARNING ---
FIN_WARN = [
    ("identity document marker", re.compile(r"\b(?:driver'?s? licen[cs]e|passport|date of birth|DOB|medicare|medicaid)\b", re.I)),
    ("credential word", re.compile(r"\b(?:password|passcode|pin ?code|recovery codes?|backup codes?|api[ _-]?key|client[ _-]?secret|access[ _-]?token)\b", re.I)),
    ("financial institution", re.compile(r"\b(?:Wealthfront|Fidelity|Vanguard|E\*?TRADE|Carta|Charles Schwab|Capital One|Quicksilver|Venture X|Bank of America|BofA|Citi(?:bank)?|Chase|Amex|American Express|Synchrony|U\.?S\.? Bank|BMO|Timberland Bank|SimpleFIN|Betterment|Robinhood)\b")),
    ("insurer", re.compile(r"\b(?:Aetna|Cigna|COBRA|State Farm|GEICO|Allstate|USAA|Liberty Mutual|Lemonade|Trupanion|Healthy Paws)\b")),
    ("finance jargon", re.compile(r"\b(?:net worth|brokerage|401\(?k\)?|Roth|backdoor|IRA|HSA|RSU|NSO|ISO|AMT|SWR|FIRE number|statement balance|credit score|credit report|Equifax|Experian|TransUnion|mortgage|escrow|payoff|premium|deductible|policy number|wire transfer|ACH|EFT)\b")),
]

ALLOW_EMAIL_DOMAINS = {"example.com", "users.noreply.github.com", "w3.org", "openstreetmap.org", "schema.org"}

failures = 0
warnings = 0
ALLOW = []  # (path_substring, compiled regex)


def load_allowlist():
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "..", "public-guard-allow.txt"), ".github/public-guard-allow.txt"):
        if os.path.exists(cand):
            with open(cand, encoding="utf-8") as f:
                for ln in f:
                    ln = ln.rstrip("\n")
                    if not ln.strip() or ln.lstrip().startswith("#"):
                        continue
                    sub, _, rx = ln.partition("  ")
                    if rx.strip():
                        ALLOW.append((sub.strip(), re.compile(rx.strip())))
            return


def allowed(path, finding):
    return any(sub in path and rx.search(finding) for sub, rx in ALLOW)


def fail(path, msg, line=None):
    global failures
    if allowed(path, msg):
        return
    failures += 1
    loc = f"file={path}" + (f",line={line}" if line else "")
    print(f"::error {loc}::{msg}")


def warn(path, msg, line=None):
    global warnings
    if allowed(path, msg):
        return
    warnings += 1
    loc = f"file={path}" + (f",line={line}" if line else "")
    print(f"::warning {loc}::{msg}")


# ---------- homes (secret) ----------
def load_homes():
    raw = os.environ.get("PRIVACY_HOMES", "").strip()
    homes = []
    for part in re.split(r"[;\n]+", raw):
        part = part.strip()
        if not part:
            continue
        la, lo = part.split(",")[:2]
        homes.append((float(la), float(lo)))
    return homes


def hav_km(a, b, c, d):
    p = math.pi / 180
    x = math.sin((c - a) * p / 2) ** 2 + math.cos(a * p) * math.cos(c * p) * math.sin((d - b) * p / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(x))


# ---------- images ----------
def exif_has_gps(path):
    """True when a JPEG/TIFF EXIF IFD0 contains the GPS IFD pointer (tag 0x8825)."""
    with open(path, "rb") as f:
        b = f.read(262144)
    i = b.find(b"Exif\x00\x00")
    if i < 0:
        # bare TIFF / HEIC: look for a TIFF header at the start
        if b[:4] not in (b"II*\x00", b"MM\x00*"):
            return False
        t = b
    else:
        t = b[i + 6:]
    if t[:2] == b"II":
        e = "<"
    elif t[:2] == b"MM":
        e = ">"
    else:
        return False
    try:
        ifd = struct.unpack(e + "I", t[4:8])[0]
        n = struct.unpack(e + "H", t[ifd:ifd + 2])[0]
        for k in range(n):
            tag = struct.unpack(e + "H", t[ifd + 2 + 12 * k:ifd + 4 + 12 * k])[0]
            if tag == 0x8825:
                return True
    except struct.error:
        return False
    return False


def png_has_location(path):
    with open(path, "rb") as f:
        b = f.read(262144)
    return b"eXIf" in b and exif_has_gps_bytes(b[b.find(b"eXIf") + 4:])


def exif_has_gps_bytes(t):
    if t[:2] == b"II":
        e = "<"
    elif t[:2] == b"MM":
        e = ">"
    else:
        return False
    try:
        ifd = struct.unpack(e + "I", t[4:8])[0]
        n = struct.unpack(e + "H", t[ifd:ifd + 2])[0]
        return any(struct.unpack(e + "H", t[ifd + 2 + 12 * k:ifd + 4 + 12 * k])[0] == 0x8825 for k in range(n))
    except struct.error:
        return False


# ---------- videos ----------
ISO6709 = re.compile(rb"[+-]\d{2,3}\.\d+[+-]\d{3}\.\d+")


def video_has_location(path):
    with open(path, "rb") as f:
        head = f.read(4 * 1024 * 1024)
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 4 * 1024 * 1024))
        tail = f.read()
    for chunk in (head, tail):
        if b"\xa9xyz" in chunk or b"com.apple.quicktime.location.ISO6709" in chunk:
            return True
        if ISO6709.search(chunk) and b"moov" in chunk:
            return True
    return False


# ---------- text ----------
def scan_text(path, homes, radius_km):
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", errors="replace")
    for m in EMAIL.finditer(text):
        dom = m.group(0).rsplit("@", 1)[1].lower()
        if dom not in ALLOW_EMAIL_DOMAINS:
            fail(path, f"e-mail address: {m.group(0)}", line_of(text, m.start()))
    for rx, label in ((PHONE, "phone number"), (SSN, "SSN-shaped number"), (CARD, "card-shaped number"),
                      (STREET, "street address"), (PRIVATE_IP, "private IP")):
        for m in rx.finditer(text):
            fail(path, f"{label}: {m.group(0)}", line_of(text, m.start()))
    for label, rx in FIN_FAIL:
        for m in rx.finditer(text):
            fail(path, f"{label}: {m.group(0)}", line_of(text, m.start()))
    for label, rx in FIN_WARN:
        seen = set()
        for m in rx.finditer(text):
            word = m.group(0)
            if word in seen:
                continue
            seen.add(word)
            warn(path, f"{label}: {word}", line_of(text, m.start()))
    if homes:
        hits = 0
        for m in PAIR.finditer(text):
            la, lo = float(m.group(1)), float(m.group(2))
            if not (-90 <= la <= 90 and -180 <= lo <= 180):
                continue
            for h in homes:
                if hav_km(la, lo, h[0], h[1]) <= radius_km:
                    hits += 1
                    if hits <= 5:
                        fail(path, f"coordinate {la},{lo} is within {int(radius_km*1000)} m of a home",
                             line_of(text, m.start()))
        if hits > 5:
            fail(path, f"... {hits} coordinates total within the privacy radius")


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


# ---------- driver ----------
def iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for fn in files:
                    yield os.path.join(root, fn)
        elif os.path.exists(p):
            yield p


def main(argv):
    radius_m = 250.0
    args = []
    it = iter(argv)
    for a in it:
        if a == "--radius-m":
            radius_m = float(next(it))
        else:
            args.append(a)
    if not args:
        print(__doc__)
        return 2
    load_allowlist()
    homes = load_homes()
    if not homes:
        warn(args[0], "PRIVACY_HOMES not set: home-proximity check skipped")
    radius_km = radius_m / 1000.0
    n = 0
    for path in iter_files(args):
        n += 1
        ext = os.path.splitext(path)[1].lower()
        size_mb = os.path.getsize(path) / 1e6
        if size_mb > MAX_PAGE_MB:
            fail(path, f"{size_mb:.0f} MB exceeds {MAX_PAGE_MB} MB (GitHub hard limit is 100 MB)")
        elif size_mb > MAX_FILE_MB and ext not in {".html", ".htm"}:
            fail(path, f"{size_mb:.0f} MB exceeds {MAX_FILE_MB} MB per-file limit")
        if ext in IMAGE_EXT:
            if (ext == ".png" and png_has_location(path)) or (ext != ".png" and exif_has_gps(path)):
                fail(path, "image carries GPS EXIF (strip with: exiftool -gps:all= FILE)")
        elif ext in VIDEO_EXT:
            if video_has_location(path):
                fail(path, "video carries a location atom (strip with: exiftool -api QuickTimeUTC -xmp:all= -quicktime:location= FILE)")
        elif ext in TEXT_EXT:
            scan_text(path, homes, radius_km)
    print(f"public_guard: {n} files scanned, {failures} failure(s), {warnings} warning(s), "
          f"radius {int(radius_m)} m, homes {'set' if homes else 'NOT SET'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
