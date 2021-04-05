## Current state
### E-Mail tests
1. "From:" different from "MAIL FROM:" ✅
2. VRFY available ✅
3. EXPN available ✅
4. Open relay ✅
5. STARTLS optional (downgrade attack) ✅
6. Malware
    - EICAR test ✅
    - Zipped EICAR test
    - PE file
    - Excel with macro
    - Word with macro
7. Server fingerprinting
8. List available commands
9. Banner grabbing
10. Check NTLM auth
11. Username enumeration, with wordlist (VRFY, EXPN or RCPT TO)
12. Message size

## DNS tests
1. Get relevant records
    - SPF ✅
    - DKIM
    - DMARC ✅
2. walk SPF records ✅
    - check registration domain entries (possible takover)
3. mail server reverse ip ✅
4. get mailservers (MX) ✅
5. get mailaddresses from ✅
    - DNS SOA ✅
    - DMARC ✅
6. Get subdomains and check for MX records
