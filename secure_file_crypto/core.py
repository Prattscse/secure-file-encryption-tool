"""File encryption and decryption helpers built on Fernet.

Fernet provides symmetric authenticated encryption: ciphertext is encrypted and
authenticated, so modified data or the wrong key is rejected during decryption.
This module deliberately uses the cryptography library rather than implementing
cryptographic primitives itself.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class FileCryptoError(Exception):
    """Base exception for expected file-encryption failures."""


def generate_key_file(key_path: str | Path, *, force: bool = False) -> Path:
    """Generate a Fernet key file without overwriting an existing file by default."""
    destination = Path(key_path).expanduser()
    _require_parent_directory(destination)
    if destination.exists() and not force:
        raise FileExistsError(f"Key file already exists: {destination}. Use --force to replace it.")

    key = Fernet.generate_key()
    _write_bytes(destination, key + b"\n", force=force, private=True)
    return destination


def load_key(key_path: str | Path) -> Fernet:
    """Load and validate a Fernet key from a key file."""
    path = Path(key_path).expanduser()
    if not path.is_file():
        raise FileCryptoError(f"Key file does not exist: {path}")
    try:
        key = path.read_bytes().strip()
        return Fernet(key)
    except (OSError, ValueError) as exc:
        raise FileCryptoError(f"Could not load a valid Fernet key from {path}") from exc


def encrypt_file(
    input_path: str | Path,
    key_path: str | Path,
    output_path: str | Path | None = None,
    *,
    force: bool = False,
) -> Path:
    """Encrypt a file and write ciphertext only after the source has been read."""
    source = Path(input_path).expanduser()
    destination = Path(output_path).expanduser() if output_path else Path(f"{source}.enc")
    key_file = Path(key_path).expanduser()
    _validate_paths(source, destination, key_file)
    if not source.is_file():
        raise FileCryptoError(f"Input file does not exist or is not a regular file: {source}")
    _check_output(destination, force=force)
    fernet = load_key(key_file)
    try:
        plaintext = source.read_bytes()
    except OSError as exc:
        raise FileCryptoError(f"Could not read input file: {source}") from exc
    ciphertext = fernet.encrypt(plaintext)
    _write_bytes(destination, ciphertext + b"\n", force=force, private=False)
    return destination


def decrypt_file(
    input_path: str | Path,
    key_path: str | Path,
    output_path: str | Path | None = None,
    *,
    force: bool = False,
) -> Path:
    """Authenticate and decrypt a Fernet token before writing any plaintext."""
    source = Path(input_path).expanduser()
    if output_path is not None:
        destination = Path(output_path).expanduser()
    elif source.name.endswith(".enc"):
        destination = source.with_name(source.name[:-4])
    else:
        destination = source.with_name(source.name + ".decrypted")
    key_file = Path(key_path).expanduser()
    _validate_paths(source, destination, key_file)
    if not source.is_file():
        raise FileCryptoError(f"Encrypted input file does not exist or is not a regular file: {source}")
    _check_output(destination, force=force)
    fernet = load_key(key_file)
    try:
        token = source.read_bytes().strip()
        plaintext = fernet.decrypt(token)
    except InvalidToken as exc:
        raise FileCryptoError("Decryption failed: token is invalid, corrupted, or encrypted with a different key") from exc
    except OSError as exc:
        raise FileCryptoError(f"Could not read encrypted input file: {source}") from exc
    _write_bytes(destination, plaintext, force=force, private=True)
    return destination


def _require_parent_directory(path: Path) -> None:
    parent = path.parent
    if not parent.exists() or not parent.is_dir():
        raise FileCryptoError(f"Parent directory does not exist: {parent}")


def _validate_paths(source: Path, destination: Path, key_file: Path) -> None:
    """Prevent replacing the source, the key, or their resolved equivalents."""
    source_resolved = source.resolve(strict=False)
    destination_resolved = destination.resolve(strict=False)
    key_resolved = key_file.resolve(strict=False)
    if source_resolved == destination_resolved:
        raise FileCryptoError("Input and output paths must be different")
    if destination_resolved == key_resolved:
        raise FileCryptoError("Output path must not be the same as the key file")


def _check_output(path: Path, *, force: bool) -> None:
    _require_parent_directory(path)
    if path.exists() and not force:
        raise FileExistsError(f"Output file already exists: {path}. Use --force to replace it.")


def _write_bytes(path: Path, data: bytes, *, force: bool, private: bool) -> None:
    """Write via a same-directory temporary file; don't clobber by default."""
    parent = path.parent
    _require_parent_directory(path)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if private and os.name == "posix":
            os.chmod(temporary, 0o600)
        if force:
            os.replace(temporary, path)
        else:
            # Hard-link creation is atomic on a single filesystem and fails if
            # the destination already exists, avoiding a check-then-write race.
            try:
                os.link(temporary, path)
            except FileExistsError:
                raise FileExistsError(f"Output file already exists: {path}. Use --force to replace it.")
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
