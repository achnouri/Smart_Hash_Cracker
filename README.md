# Smart Hash Cracker — README (short)

##### - smart tool for MD5, SHA1, and SHA256 using a wordlist<br><br>


**- Run the script:**

```bash
python3 smart_hash_cracker.py
```
<br>


```
$ python3 smart_hash_cracker.py 

===============================================
Smart Hash Cracker
===============================================
1) Detect hash type
2) Hash plaintext (md5/sha1/sha256)
3) Crack hash using wordlist
4) Exit
===============================================
Choose an option:
```

<br><br>


**- What the Smart-Hash-Cracker tool can do ?**

    - Detect hash type by length (MD5, SHA1, SHA256)

    - Compute a hash for given plaintext (md5/sha1/sha256)

    - Crack a target hash using a newline wordlist

    - Uses multiple processes to speed up the search

    - Reads the wordlist into memory (chunk size/processes for large files or low RAM)
    
    -Print clear results: found plaintext + timing, or “not found”

<br><br>

:) Use only on hashes you own or are authorized to test (like CTFs) <br><br>

---

###### Created by achnouri