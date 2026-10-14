# Secure File Encryption & Decryption Tool

A Python command-line utility for encrypting and decrypting local files using authenticated symmetric encryption through the `cryptography` library. It generates a Fernet key, encrypts files, and verifies ciphertext integrity during decryption.

This is a focused learning project for understanding symmetric encryption, key handling, binary file I/O, validation, and failure handling. It uses an established cryptography library rather than implementing cryptographic algorithms from scratch.

## Features

- Generate a random Fernet key and save it to a separate key file.
- Encrypt files using Fernet authenticated encryption.
- Decrypt files only when authentication succeeds.
- Support custom input, output, and key paths.
- Refuse to overwrite an existing output unless `--force` is supplied.
- Reject identical input and output paths to avoid replacing the source file.
- Handle missing files, malformed keys, modified ciphertext, and wrong-key errors without writing decrypted output.
- Include unit tests and a GitHub Actions workflow for Python 3.10, 3.11, and 3.12.

## Requirements

- Python 3.10 or newer
- `cryptography`

## Setup

Clone the repository, create a virtual environment, and install dependencies.

```bash
git clone https://github.com/Prattscse/secure-file-encryption-tool.git
cd secure-file-encryption-tool
python -m venv .venv
```

Activate the environment.

**Windows PowerShell**

```powershell
.venv\Scripts\Activate.ps1
```

**macOS/Linux**

```bash
source .venv/bin/activate
```

Install the requirements:

```bash
python -m pip install -r requirements.txt
```

To run the tests, install the development dependencies as well:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Usage

The tool can be run as a module from the project directory.

### 1. Generate a key

```bash
python -m secure_file_crypto.cli keygen --key-file secret.key
```

This writes a randomly generated Fernet key to `secret.key`. Keep the key private and backed up securely. Anyone with the key can decrypt files encrypted with it.

### 2. Encrypt a file

```bash
python -m secure_file_crypto.cli encrypt --input notes.txt --key-file secret.key
```

By default, the encrypted file is written to `notes.txt.enc`. Specify a different location with `--output`:

```bash
python -m secure_file_crypto.cli encrypt --input notes.txt --key-file secret.key --output backup.enc
```

### 3. Decrypt a file

```bash
python -m secure_file_crypto.cli decrypt --input notes.txt.enc --key-file secret.key --output recovered-notes.txt
```

For a file named `notes.txt.enc`, the default output is `notes.txt`. If that file already exists (for example, because you kept the original plaintext), the operation stops rather than silently overwriting it. Use a different `--output` such as `recovered-notes.txt`, or deliberately pass `--force` to replace an existing output.

### Optional: replace an output file

Use `--force` only when you are certain the target file can be replaced. For example:

```bash
python -m secure_file_crypto.cli encrypt --input notes.txt --key-file secret.key --output backup.enc --force
```

### Installed command

To install the project in editable mode, run `python -m pip install -e .`. Then use `secure-file keygen`, `secure-file encrypt`, and `secure-file decrypt` with the same options.

## How it works

1. A Fernet key is generated using the `cryptography` package.
2. The tool loads the key from a user-specified file.
3. During encryption, the selected file is read as bytes and encrypted into a Fernet token.
4. During decryption, Fernet verifies authenticity before returning plaintext. The tool writes output only after successful authentication.
5. Output files are written through a temporary file and published without replacing an existing path by default.

Fernet combines symmetric encryption with message authentication. If ciphertext has been modified or the key is incorrect, decryption fails.

## Key handling and security notes

- **Keep the key separate from the encrypted file.** If someone obtains both the ciphertext and key, they can decrypt the content.
- **Losing the key means the data cannot be recovered by this tool.** There is no password reset or key recovery feature.
- **Do not upload real keys or private files to GitHub.** The included `.gitignore` excludes common key and encrypted-file extensions, but always review `git status` before committing.
- The key file is not encrypted with a password. Protect it using operating-system permissions or an appropriate secrets-management solution.
- The tool uses the Fernet format provided by `cryptography`; it does not implement custom cryptographic primitives.
- This implementation reads the entire input file into memory. It is intended for modest-sized files, not very large archives or streaming workloads.
- File encryption does not protect a machine that is already compromised, prevent deletion, or secure backups automatically.
- The key file and output file are written with owner-only permissions on POSIX systems where supported. Windows file permission behavior depends on the filesystem and account configuration.

## Project structure

```text
secure-file-encryption-tool/
├── .github/workflows/tests.yml
├── example/
│   ├── README.md
│   └── sample.txt
├── secure_file_crypto/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   └── core.py
├── tests/
│   ├── test_cli.py
│   └── test_core.py
├── .gitignore
├── LICENSE
├── pyproject.toml
├── requirements-dev.txt
└── requirements.txt
```

## Limitations

This project demonstrates a basic file-encryption workflow. It is not a full key-management product, enterprise file vault, or independently audited security tool. It does not provide password-derived keys, key rotation, streaming encryption, secure deletion of plaintext, or metadata hiding. Fernet includes a timestamp in its token format, so it should not be described as concealing all metadata.

For sensitive production data, evaluate your organization's key-management requirements and use reviewed tools and processes.

## License

MIT. See [LICENSE](LICENSE).
