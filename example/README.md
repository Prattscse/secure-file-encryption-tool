# Example workflow

Run these commands from the repository root after installing requirements.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

python -m secure_file_crypto.cli keygen --key-file local.key
python -m secure_file_crypto.cli encrypt --input example/sample.txt --key-file local.key
python -m secure_file_crypto.cli decrypt --input example/sample.txt.enc --key-file local.key --output example/recovered-sample.txt
```

The key and encrypted output are deliberately excluded from version control.
