#!/usr/bin/env python3
"""
Verify the tamper-evident hash chain of an xxl-job hardened security log.

Each process start writes a genesis line:
    severity=INFO event=SECURITY_LOG_CHAIN_START seq=0 genesis="<hex>"
then each event line ends with:
    ... seq=<n> chain=<first 16 hex of sha256(prev_head + "|" + payload)>

Usage: verify_chain.py <security.log> [more.log ...]
Exit code 0 = intact, 1 = broken (edited / deleted / reordered lines), 2 = no chain found.
"""
import hashlib
import re
import sys

LOGGER = "xxl-job-security"
GENESIS_RE = re.compile(r'event=SECURITY_LOG_CHAIN_START seq=0 genesis="([0-9a-f]{64})"')
SEQ_RE = re.compile(r' seq=(\d+)$')


def extract_message(line):
    idx = line.find(LOGGER)
    if idx < 0:
        return None
    sep = line.find(" - ", idx)
    if sep < 0:
        return None
    msg = line[sep + 3:].rstrip("\r\n")
    return msg if msg.startswith("severity=") else None


def verify(paths):
    head, expected_seq, chains, errors, events = None, None, 0, [], 0
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            for num, line in enumerate(f, 1):
                msg = extract_message(line)
                if msg is None:
                    continue
                genesis = GENESIS_RE.search(msg)
                if genesis:
                    head, expected_seq = genesis.group(1), 1
                    chains += 1
                    continue
                if head is None:
                    errors.append(f"{path}:{num}: event before any genesis line")
                    continue
                cut = msg.rfind(" chain=")
                if cut < 0:
                    errors.append(f"{path}:{num}: missing chain field")
                    continue
                payload, chain = msg[:cut], msg[cut + 7:]
                seq = SEQ_RE.search(payload)
                if not seq or int(seq.group(1)) != expected_seq:
                    errors.append(f"{path}:{num}: seq gap, expected {expected_seq}, got {seq.group(1) if seq else None} (lines deleted?)")
                    expected_seq = int(seq.group(1)) if seq else expected_seq
                head = hashlib.sha256((head + "|" + payload).encode("utf-8")).hexdigest()
                if head[:16] != chain:
                    errors.append(f"{path}:{num}: chain mismatch (line edited or reordered)")
                expected_seq += 1
                events += 1
    return chains, events, errors


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    chains, events, errors = verify(sys.argv[1:])
    if chains == 0:
        print("NO CHAIN: no genesis line found")
        return 2
    if errors:
        print(f"BROKEN: {len(errors)} problem(s) in {events} event(s), {chains} chain(s)")
        for err in errors[:50]:
            print("  " + err)
        return 1
    print(f"OK: {events} event(s) in {chains} chain(s) verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
