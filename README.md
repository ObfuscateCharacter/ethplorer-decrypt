# ethplorer-decrypt


Writing

This script decrypts API responses from [Ethplorer](<https://ethplorer.io>).

## Usage

### As a Python Module

```
import json
from ethplorer_decrypt import decrypt_payload, fetch_address_data

data = fetch_address_data("0x307576dd4f73f91bb8c4a2edb762938e8e067d31")
print(json.dumps(data, indent=2)[:2000])
```

### Command-Line Interface (CLI)

Decrypt an address payload:

```
python ethplorer_decrypt.py <address>
```

Decrypt a saved API response from a JSON file:

```
python ethplorer_decrypt.py --file payload.json
```
