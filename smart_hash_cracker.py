"""
smart_hash_cracker.py

Usage:
    python3 smart_hash_cracker.py

Author: achnouri
"""

import hashlib
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Callable, Optional, List


def detect_hash_type(h: str) -> Optional[str]:
    """return 'md5', 'sha1', 'sha256' or none for unknown based on length"""
    if not h:
        return None
    length = len(h.strip())
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    return None

def get_hasher(algo: str) -> Callable[[str], str]:
    """return a function that computes the given hash hex digest for a text input"""
    algo = algo.lower()
    if algo == "md5":
        return lambda s: hashlib.md5(s.encode(errors="ignore")).hexdigest()
    if algo == "sha1":
        return lambda s: hashlib.sha1(s.encode(errors="ignore")).hexdigest()
    if algo == "sha256":
        return lambda s: hashlib.sha256(s.encode(errors="ignore")).hexdigest()
    raise ValueError("Unsupported algorithm: " + algo)


def worker_check_chunk(chunk: List[str], target: str, algo: str) -> Optional[str]:
    """check a chunk (list) of candidate strings"""
    """return matched plaintext or None"""
    """This function is executed in a separate process"""

    hasher = get_hasher(algo)
    target = target.lower()
    for candidate in chunk:
        s = candidate.rstrip("\r\n")
        if not s:
            continue
        try:
            if hasher(s) == target:
                return s
        except Exception:
            continue
    return None


def crack_hash_from_file(target_hash: str, filename: str, algo: Optional[str] = None, processes: int = None, chunk_size: int = 4000):
    """ attempt to find the plaintext for `target_hash` using `filename` as a newline-delimited wordlist"""
    """Splits the list into chunks and processes them in parallel"""
    """- processes: number of worker processes (None -> os.cpu_count())"""
    """- chunk_size: how many lines per chunk (tune for memory vs speed)"""

    if not os.path.isfile(filename):
        print("Error: wordlist file not found:", filename)
        return None

    if algo is None:
        algo = detect_hash_type(target_hash)
        if algo is None:
            print("Error: unknown hash length. Provide MD5/SHA1/SHA256 hash or specify algorithm.")
            return None

    target_hash = target_hash.strip().lower()
    processes = processes or os.cpu_count() or 1
    total_lines = 0

    print(f"Reading wordlist '{filename}' ...")

    with open(filename, mode="r", errors="ignore") as f:
        lines = f.readlines()
        total_lines = len(lines)

    if total_lines == 0:
        print("Wordlist is empty.")
        return None

    chunks = [lines[i:i+chunk_size] for i in range(0, total_lines, chunk_size)]

    print(f"Total candidates: {total_lines}  -> {len(chunks)} chunk(s) of up to {chunk_size} lines")
    print(f"Using algorithm: {algo.upper()}  |  Processes: {processes}")

    start_time = time.time()
    checked = 0
    found_plain = None

    with ProcessPoolExecutor(max_workers=processes) as exe:
        
        future_to_chunk_idx = {exe.submit(worker_check_chunk, chunk, target_hash, algo): idx for idx, chunk in enumerate(chunks)}

        try:
            for future in as_completed(future_to_chunk_idx):

                idx = future_to_chunk_idx[future]
                result = future.result()
                chunk_len = len(chunks[idx])
                checked += chunk_len
                elapsed = max(1e-6, time.time() - start_time)
                rate = checked / elapsed

                print(f"[+]{checked}/{total_lines} candidates checked ({rate:.0f} cps) ...", end="\r", flush=True)
                
                if result:
                    found_plain = result
                    for f in future_to_chunk_idx:
                        if not f.done():
                            f.cancel()
                    break
                
        except KeyboardInterrupt:
            print("\nInterrupted by user, shutting down workers...")
            exe.shutdown(wait=False)
            raise

    elapsed_total = time.time() - start_time
    print()

    if found_plain:
        print(f"[FOUND] plaintext: {found_plain!r}  (checked {checked} candidates in {elapsed_total:.2f}s)")
        return found_plain

    else:
        print(f"[-] Not found in wordlist (checked {checked} candidates in {elapsed_total:.2f}s).")
        return None


def main():

    print(r"""
    --------------------------------------------------------
    --| | | | __ _ ___| |__  -------------------------------
    --| |_| |/ _` / __| '_ \  ------------------------------
    --|  _  | (_| \__ \ | | | ------------------------------
    --|_| |_|\__,_|___/_| |_| ------------------------------
    --------------------------------------------------------                                                        
    -- HASH -- CRACKER -- TOOL -- -- -- -- -- achnouri -----
    --------------------------------------------------------

    """)

    print("===============================================")
    print("Smart Hash Cracker")
    print("===============================================")
    print("1) Detect hash type")
    print("2) Hash plaintext (md5/sha1/sha256)")
    print("3) Crack hash using wordlist")
    print("4) Exit")
    print("===============================================")
    print();

    choice = input("Choose an option: ").strip()

    if choice == "1":

        h = input("Enter hash: ").strip()
        t = detect_hash_type(h)
        print("Detected:", t.upper() if t else "Unknown")

    elif choice == "2":

        algo = input("Algorithm (md5/sha1/sha256) [md5]: ").strip() or "md5"
        txt = input("Enter text: ")

        try:
            print(get_hasher(algo)(txt))
        except Exception as e:
            print("Error:", e)

    elif choice == "3":

        target = input("Enter hash to crack: ").strip()

        if not target:
            print("No hash provided.")
            return

        algo = detect_hash_type(target)

        if not algo:
            
            print("Hash length doesn't match known MD5/SHA1/SHA256 !")
            algo = input("Specify algorithm (md5/sha1/sha256) or press Enter to abort: ").strip().lower()

            if not algo:
                print("Aborting!")
                return

            if algo not in ("md5", "sha1", "sha256"):
                print("Unsupported algorithm:", algo)
                return

        filename = input("Wordlist file path: ").strip()

        if not filename:
            print("No wordlist provided!")
            return

        try:
            procs = input(f"Worker processes [default={os.cpu_count() or 1}]: ").strip()
            procs = int(procs) if procs else None
        except ValueError:
            procs = None

        crack_hash_from_file(target, filename, algo=algo, processes=procs)

    elif choice == "4":
        print("Exiting")

    else:
        print("Invalid option, exiting")

if __name__ == "__main__":

    try:
        main()
    except Exception as e:
        print("Fatal error:", type(e).__name__, e)
        sys.exit(1)
