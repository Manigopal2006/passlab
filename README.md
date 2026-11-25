# PassLab

A local C command-line password auditor and password encryption utility.

## Build and run

Requires a C compiler, OpenSSL development headers/libraries, and `make`.

```sh
make
./passlab
```

## Features

- Checks lowercase, uppercase, digit, and special-character presence.
- Flags adjacent repeated characters, alternating repeats, and ascending or descending adjacent character runs.
- Reports a rough entropy estimate with a qualitative risk band. It deducts for short length and detected patterns; it cannot identify dictionary words, breached passwords, reuse, or all human-chosen patterns.
- Encrypts a password using AES-256-GCM with a random salt and nonce, PBKDF2-HMAC-SHA-256 key derivation, and 300,000 iterations. The output is hexadecimal (`PWA1` prefix), so it is alphanumeric.
- Decrypts that text when given the original encryption key. A lost key cannot be recovered.

The encryption key must be different from the password being encrypted. Use a strong memorable key and store it separately from the ciphertext. This tool keeps input in process memory only; it does not save passwords or ciphertext to files. Avoid pasting secrets into terminals or shell history. Terminal input is hidden when connected to a terminal.

The auditor is a heuristic, not a password-cracking benchmark. Prefer a unique, randomly generated password stored in a reputable password manager; encrypting a weak password does not make it safe to reuse or use for an online account.
