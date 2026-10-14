from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from secure_file_crypto.core import (
    FileCryptoError, decrypt_file, encrypt_file, generate_key_file, load_key,
)


def test_encrypt_then_decrypt_round_trip(tmp_path: Path):
    key_path = tmp_path / "secret.key"
    source = tmp_path / "notes.txt"
    source.write_bytes(b"Private notes\x00\xff\nsecond line")
    generate_key_file(key_path)

    encrypted = encrypt_file(source, key_path)
    assert encrypted == tmp_path / "notes.txt.enc"
    original_bytes = source.read_bytes()
    assert encrypted.read_bytes() != original_bytes

    # The tool should not overwrite an existing plaintext file automatically.
    source.unlink()
    decrypted = decrypt_file(encrypted, key_path)
    assert decrypted == source.with_name("notes.txt")
    assert decrypted.read_bytes() == original_bytes


def test_decryption_with_wrong_key_fails_without_writing_output(tmp_path: Path):
    key1, key2 = tmp_path / "one.key", tmp_path / "two.key"
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample payload")
    generate_key_file(key1)
    generate_key_file(key2)
    encrypted = encrypt_file(source, key1)
    output = tmp_path / "recovered.bin"

    with pytest.raises(FileCryptoError, match="Decryption failed"):
        decrypt_file(encrypted, key2, output)
    assert not output.exists()


def test_modified_ciphertext_fails_authentication(tmp_path: Path):
    key_path, source = tmp_path / "secret.key", tmp_path / "plain.txt"
    source.write_text("original content", encoding="utf-8")
    generate_key_file(key_path)
    encrypted = encrypt_file(source, key_path)
    token = bytearray(encrypted.read_bytes().strip())
    token[-5] = ord("A") if token[-5] != ord("A") else ord("B")
    encrypted.write_bytes(bytes(token))

    with pytest.raises(FileCryptoError, match="Decryption failed"):
        decrypt_file(encrypted, key_path, tmp_path / "out.txt")
    assert not (tmp_path / "out.txt").exists()


def test_existing_outputs_are_not_overwritten_by_default(tmp_path: Path):
    key_path, source = tmp_path / "secret.key", tmp_path / "plain.txt"
    key_path.write_bytes(Fernet.generate_key())
    source.write_text("payload", encoding="utf-8")
    destination = tmp_path / "plain.txt.enc"
    destination.write_text("keep me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        encrypt_file(source, key_path)
    assert destination.read_text(encoding="utf-8") == "keep me"


def test_input_and_output_must_differ(tmp_path: Path):
    key_path, source = tmp_path / "secret.key", tmp_path / "plain.txt"
    generate_key_file(key_path)
    source.write_text("payload", encoding="utf-8")
    with pytest.raises(FileCryptoError, match="must be different"):
        encrypt_file(source, key_path, source)


def test_keygen_does_not_overwrite_existing_key(tmp_path: Path):
    key_path = tmp_path / "secret.key"
    generate_key_file(key_path)
    original = key_path.read_bytes()
    with pytest.raises(FileExistsError):
        generate_key_file(key_path)
    assert key_path.read_bytes() == original


def test_invalid_key_is_rejected(tmp_path: Path):
    key_path = tmp_path / "bad.key"
    key_path.write_text("not-a-fernet-key", encoding="utf-8")
    with pytest.raises(FileCryptoError, match="valid Fernet key"):
        load_key(key_path)


def test_invalid_ciphertext_does_not_create_output(tmp_path: Path):
    key_path, encrypted = tmp_path / "secret.key", tmp_path / "damaged.enc"
    generate_key_file(key_path)
    encrypted.write_bytes(b"this is not a Fernet token")
    output = tmp_path / "decrypted.txt"
    with pytest.raises(FileCryptoError, match="Decryption failed"):
        decrypt_file(encrypted, key_path, output)
    assert not output.exists()


def test_custom_output_paths_work(tmp_path: Path):
    key_path = tmp_path / "secret.key"
    source = tmp_path / "original.dat"
    source.write_bytes(bytes(range(256)))
    generate_key_file(key_path)
    encrypted = encrypt_file(source, key_path, tmp_path / "ciphertext.bin")
    decrypted = decrypt_file(encrypted, key_path, tmp_path / "recovered.dat")
    assert decrypted.read_bytes() == source.read_bytes()


def test_missing_input_reports_clear_error(tmp_path: Path):
    key_path = tmp_path / "secret.key"
    generate_key_file(key_path)
    with pytest.raises(FileCryptoError, match="does not exist"):
        encrypt_file(tmp_path / "missing.txt", key_path)


def test_output_must_not_replace_key_file(tmp_path: Path):
    key_path = tmp_path / "secret.key"
    source = tmp_path / "plain.txt"
    generate_key_file(key_path)
    original_key = key_path.read_bytes()
    source.write_text("payload", encoding="utf-8")

    with pytest.raises(FileCryptoError, match="must not be the same as the key file"):
        encrypt_file(source, key_path, key_path, force=True)
    assert key_path.read_bytes() == original_key
