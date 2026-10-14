from pathlib import Path

from secure_file_crypto.cli import main


def test_cli_keygen_encrypt_decrypt(tmp_path: Path, capsys):
    key_path = tmp_path / "work.key"
    input_path = tmp_path / "message.txt"
    input_path.write_text("test message", encoding="utf-8")

    assert main(["keygen", "--key-file", str(key_path)]) == 0
    assert main(["encrypt", "--input", str(input_path), "--key-file", str(key_path)]) == 0
    encrypted = tmp_path / "message.txt.enc"
    assert encrypted.exists()
    # Preserve the original overwrite guard; remove the plaintext before testing default output.
    input_path.unlink()
    assert main(["decrypt", "--input", str(encrypted), "--key-file", str(key_path)]) == 0
    assert input_path.read_text(encoding="utf-8") == "test message"
    assert "File decrypted and authenticated" in capsys.readouterr().out


def test_cli_returns_nonzero_on_invalid_key(tmp_path: Path, capsys):
    input_path, key_path = tmp_path / "message.txt", tmp_path / "bad.key"
    input_path.write_text("test", encoding="utf-8")
    key_path.write_text("invalid", encoding="utf-8")
    assert main(["encrypt", "--input", str(input_path), "--key-file", str(key_path)]) == 2
    assert "valid Fernet key" in capsys.readouterr().err
