"""
ethplorer_decrypt.py — decrypts ethplorer.io's obfuscated internal API responses.

The site's frontend (webpack module `789` in its address-page bundle) processes
responses shaped like {"v":2, "obj":"44.16", "data":"<base64>"} as follows:

    1. raw   = base64_decode(data)
    2. off, len = obj.split(".")           # e.g. "44.16" -> offset 44, len 16
       key  = raw[off : off+len]           # the XOR key is EMBEDDED in the data
    3. body = raw[:off] + raw[off+len:]    # data with the key segment removed
    4. out  = body XOR repeat(key)         # repeating-key XOR
    5. out is gzip (1f 8b ...) -> gunzip -> JSON string

Endpoints known to use this scheme:
    https://ethplorer.io/service/service.php?tabName=transfers&data=<address>&...
    https://api2.ethplorer.io/getTopRichAddresses?...

Usage:
    from ethplorer_decrypt import decrypt_payload, fetch_address_data
    data = fetch_address_data("0x307576dd4f73f91bb8c4a2edb762938e8e067d31")
    print(json.dumps(data, indent=2)[:2000])

    CLI:
    python ethplorer_decrypt.py <address>            # decrypt address payload
    python ethplorer_decrypt.py --file payload.json  # decrypt a saved response
"""

from __future__ import annotations

import base64
import gzip
import json
import zlib
from typing import Any, Dict, Union

import requests

SITE = "https://ethplorer.io"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def decrypt_payload(payload: Dict[str, Any]) -> Union[dict, list, str]:
    """
    Decrypt one {"v":2,"obj":"44.16","data":"..."} response.
    Non-encrypted (v != 2) payloads are returned untouched.
    """
    if payload.get("v") != 2 or "data" not in payload or "obj" not in payload:
        return payload

    raw = base64.b64decode(payload["data"])
    off_s, len_s = str(payload["obj"]).split(".", 1)
    off, ln = int(off_s), int(len_s)

    key = raw[off:off + ln]
    body = raw[:off] + raw[off + ln:]

    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(body))

    if out[:2] == b"\x1f\x8b":                      # gzip magic
        out = gzip.decompress(out)
    elif out[:1] == b"\x78":                        # zlib
        out = zlib.decompress(out)

    text = out.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "application/json"})
    return s


def fetch_address_data(address: str, tab: str = "transfers", timeout: float = 20.0) -> Any:
    """Fetch + decrypt the address page payload (transfers tab by default)."""
    from urllib.parse import quote
    s = _session()
    url = f"{SITE}/service/service.php"
    params = {
        "tabName": tab,
        "data": address.lower(),
        "page": f"tab%3Dtab-{tab}%26pageTab%3D{tab}",
        "showTx": "all",
        "pricedOnly": "true",
        "selectedType": "all",
    }
    r = s.get(url, params=params, timeout=timeout)
    r.raise_for_status()
    return decrypt_payload(r.json())


def fetch_rich_list(page: int = 1, page_size: int = 50, timeout: float = 20.0) -> Any:
    """Fetch + decrypt the rich-list payload (api2 host, same scheme)."""
    s = _session()
    url = "https://api2.ethplorer.io/getTopRichAddresses"
    params = {"apiKey": "ethplorer.widget2", "index": "true",
              "page": page, "pageSize": page_size}
    r = s.get(url, params=params, timeout=timeout)
    r.raise_for_status()
    return decrypt_payload(r.json())


def summarize(data: Any) -> str:
    """Human-readable one-screen summary of a decrypted address payload."""
    if not isinstance(data, dict) or "balances" not in data:
        return json.dumps(data, indent=2, ensure_ascii=False)[:3000]
    L = []
    try:
        bal = float(data.get("balance") or 0)
    except (TypeError, ValueError):
        bal = 0.0
    rate = (data.get("ethPrice") or {}).get("rate") or 0
    L.append(f"Address      : {data.get('contract', {}).get('address', '?')}")
    L.append(f"Contract     : {'yes' if data.get('isContract') else 'no'}")
    L.append(f"ETH balance  : {bal:,.4f} ETH  (${bal*rate:,.2f})")
    L.append(f"Tokens       : {data.get('balancesTotal')} (ERC-721: {data.get('balancesERC721Total')}, ERC-1155: {data.get('balancesERC1155Total')})")
    L.append(f"Tokens value : ${data.get('balancesTotalUsdValue') or 0:,.2f}")
    L.append(f"Transfers    : {data.get('transfersCount'):,}   Tx's: {data.get('txsCount'):,}")
    rows = (data.get("balances") or [])[:8]
    if rows:
        L.append("\nTop token balances:")
        for b in rows:
            toks = data.get("tokens") or {}
            t = toks.get(b.get("contract")) or {}
            usd = b.get("usdValue")
            try:
                usd = float(usd)
            except (TypeError, ValueError):
                usd = None
            try:
                raw = int(b.get("rawBalance") or 0)
                amt = raw / (10 ** int(t.get("decimals") or 0))
                amt_s = f"{amt:,.4f}"
            except Exception:
                amt_s = str(b.get("balance"))
            L.append(f"  {t.get('symbol','?'):<10} {amt_s:>18}   ${usd:,.2f}" if isinstance(usd, (int, float))
                     else f"  {t.get('symbol','?'):<10} {amt_s:>18}")
    txs = data.get("transfers") or []
    if txs:
        L.append("\nRecent transfers:")
        import time as _t
        for x in txs[:8]:
            ts = _t.strftime("%m-%d %H:%M", _t.gmtime(x.get("timestamp", 0)))
            toks = data.get("tokens") or {}
            sym = (toks.get(x.get("contract")) or {}).get("symbol", "ETH" if x.get("isEth") else "?")
            dec = int((toks.get(x.get("contract")) or {}).get("decimals") or 18) if not x.get("isEth") else 18
            amt = (x.get("intValue") or 0) / (10 ** dec)
            if amt == 0:
                amt_s = "0"
            elif amt < 0.001:
                amt_s = f"{amt:.8f}".rstrip("0").rstrip(".")
            else:
                amt_s = f"{amt:,.4f}"
            direction = "IN " if x.get("to") and x.get("to").lower() == data.get("contract", {}).get("address", "").lower() else "OUT"
            L.append(f"  {ts}  {direction}  {amt_s:>18} {sym:<7} {str(x.get('transactionHash'))[:18]}…")
    return "\n".join(L)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("address", nargs="?", help="ethereum address")
    ap.add_argument("--file", help="decrypt a saved JSON response instead")
    ap.add_argument("--out", help="save full decrypted JSON here")
    ap.add_argument("--rich", action="store_true", help="decrypt the rich list")
    ap.add_argument("--summary", action="store_true", help="human-readable summary")
    a = ap.parse_args()

    if a.file:
        data = decrypt_payload(json.load(open(a.file)))
    elif a.rich:
        data = fetch_rich_list()
    else:
        if not a.address:
            ap.error("give an address or --file")
        data = fetch_address_data(a.address)

    if a.summary:
        print(summarize(data))
    else:
        text = json.dumps(data, indent=2, ensure_ascii=False)
        if a.out:
            open(a.out, "w").write(text)
            print(f"saved -> {a.out}  ({len(text):,} chars)")
        print(text[:3000])
        if len(text) > 3000:
            print(f"\n... [{len(text):,} chars total; use --out for the full dump]")
