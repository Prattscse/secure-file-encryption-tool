"""Command-line interface for the secure file encryption tool."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secure_file_crypto import __version__
from secure_file_crypto.core import FileCryptoError, decrypt_file, encrypt_file, generate_key_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-file",
        description="Encrypt and decrypt files using authenticated symmetric encryption (Fernet).",
        epilog="Keep your key file private and separate from encrypted files. There is no key recovery.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="Generate a new encryption key file")
    keygen.add_argument("--key-file", default="secret.key", help="Where to save the key (default: secret.key)")
    keygen.add_argument("--force", action="store_true", help="Replace an existing output file")

    encrypt = commands.add_parser("encrypt", help="Encrypt a file")
    encrypt.add_argument("--input", required=True, help="Plaintext file to encrypt")
    encrypt.add_argument("--key-file", default="secret.key", help="Path to the Fernet key file")
    encrypt.add_argument("--output", help="Encrypted output path (default: INPUT.enc)")
    encrypt.add_argument("--force", action="store_true", help="Replace an existing output file")

    decrypt = commands.add_parser("decrypt", help="Decrypt a file")
    decrypt.add_argument("--input", required=True, help="Encrypted Fernet token file")
    decrypt.add_argument("--key-file", default="secret.key", help="Path to the Fernet key file")
    decrypt.add_argument("--output", help="Plaintext output path (default: remove .enc suffix)")
    decrypt.add_argument("--force", action="store_true", help="Replace an existing output file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "keygen":
            path = generate_key_file(args.key_file, force=args.force)
            print(f"Key generated: {path}")
            print("Keep this key private. Losing it means encrypted files cannot be recovered.")
        elif args.command == "encrypt":
            path = encrypt_file(args.input, args.key_file, args.output, force=args.force)
            print(f"File encrypted: {path}")
        elif args.command == "decrypt":
            path = decrypt_file(args.input, args.key_file, args.output, force=args.force)
            print(f"File decrypted and authenticated: {path}")
        return 0
    except FileExistsError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except (FileCryptoError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
