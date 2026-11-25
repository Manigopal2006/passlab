# PassLab

A local C command-line password auditor and password encryption utility.

## Build and run

Requires a C compiler, OpenSSL development headers/libraries, and `make`. Install the OpenSSL development package first if `openssl/evp.h` is missing:

```sh
# macOS (Homebrew)
brew install openssl@3 pkg-config

# Debian or Ubuntu
sudo apt install build-essential libssl-dev pkg-config

# Fedora
sudo dnf install gcc make openssl-devel pkgconf-pkg-config
```

The Makefile reads OpenSSL's include and library paths through `pkg-config` when available.

```sh
make
./passlab
```

## Features

- Checks lowercase, uppercase, digit, and special-character presence.
- Flags adjacent repeated characters, alternating repeats, and ascending or descending adjacent character runs.
- Reports a rough entropy estimate with a qualitative risk band. It deducts for short length and detected patterns; it cannot identify dictionary words, breached passwords, reuse, or all human-chosen patterns.
- Creates an encryption key on first launch and keeps it in an in-memory credential table until exit. Encrypt and decrypt actions reuse the current key.
- Lets you change the key after verifying the current key. It retains earlier keys in RAM for that run, so existing ciphertext can still be decrypted. Ciphertext includes a key slot identifier and uses AES-256-GCM with a random salt and nonce, PBKDF2-HMAC-SHA-256 key derivation, and 300,000 iterations. The output is hexadecimal (`PWA2` prefix), so it is alphanumeric.
- The key table is cleared when the program exits. Keys are not persisted across launches; ciphertext made with a changed key can only be decrypted during the session that retains that key. A debugger with permission to inspect the running process can inspect RAM; ordinary C code cannot make process memory inaccessible to such a debugger.

The encryption key must be different from the password being encrypted. Use a strong memorable key and store it separately from the ciphertext. The menu stays open for multiple audit, encrypt, decrypt, and key-change actions. The key is never saved to disk or included in the ciphertext. This tool keeps input in process memory only; it does not save passwords or ciphertext to files. Avoid pasting secrets into terminals or shell history. Terminal input is hidden when connected to a terminal.

The auditor is a heuristic, not a password-cracking benchmark. Prefer a unique, randomly generated password stored in a reputable password manager; encrypting a weak password does not make it safe to reuse or use for an online account.
