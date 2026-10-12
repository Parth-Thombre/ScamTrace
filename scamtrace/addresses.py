"""Find candidates, then validate them independently of the language model.

An EVM address doesn't tell us whether it holds ETH, USDT, or USDC. Preserve
network + context rather than guessing an asset from the address shape.
"""
import hashlib
import re
from urllib.parse import unquote

from .models import Address

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{40}|[13][1-9A-HJ-NP-Za-km-z]{25,34}"
    r"|T[1-9A-HJ-NP-Za-km-z]{33}|(?:bc1|BC1)[A-Za-z0-9]{11,87})(?![A-Za-z0-9])"
)


def base58check(value: str) -> bytes | None:
    try:
        number = 0
        for char in value:
            number = number * 58 + BASE58.index(char)
        raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
        raw = b"\0" * (len(value) - len(value.lstrip("1"))) + raw
        payload, checksum = raw[:-4], raw[-4:]
        expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return payload if checksum == expected else None
    except ValueError:
        return None


def valid_segwit(value: str) -> bool:
    # BIP-173 / BIP-350: v0 uses Bech32; v1+ uses Bech32m.
    if value != value.lower() and value != value.upper():
        return False
    value = value.lower()
    if len(value) > 90 or not value.startswith("bc1"):
        return False
    try:
        data = [BECH32.index(char) for char in value[3:]]
    except ValueError:
        return False
    if len(data) < 7 or data[0] > 16:
        return False
    expanded = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    check = 1
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    for number in expanded + data:
        top = check >> 25
        check = ((check & 0x1FFFFFF) << 5) ^ number
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                check ^= generator
    if check != (1 if data[0] == 0 else 0x2BC830A3):
        return False
    bits = 0
    accumulator = 0
    decoded = []
    for number in data[1:-6]:
        accumulator = (accumulator << 5) | number
        bits += 5
        while bits >= 8:
            bits -= 8
            decoded.append((accumulator >> bits) & 255)
    if bits >= 5 or ((accumulator << (8 - bits)) & 255):
        return False
    return 2 <= len(decoded) <= 40 and (data[0] != 0 or len(decoded) in (20, 32))


def validate(value: str) -> tuple[str, str] | None:
    if value.startswith("0x"):
        body = value[2:]
        if len(body) != 40 or not re.fullmatch(r"[0-9a-fA-F]{40}", body):
            return None
        if body.islower() or body.isupper() or body.isdigit():
            return "EVM", "valid format; no checksum supplied"
        from Crypto.Hash import keccak

        digest = keccak.new(digest_bits=256, data=body.lower().encode()).hexdigest()
        expected = "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(body.lower()))
        return ("EVM", "EIP-55 checksum") if body == expected else None
    if value.lower().startswith("bc1"):
        return ("BTC", "Bech32/Bech32m checksum") if valid_segwit(value) else None
    payload = base58check(value)
    if payload is None or len(payload) != 21:
        return None
    if payload[0] == 0x41 and value.startswith("T"):
        return "TRON", "Base58Check checksum"
    if payload[0] in (0, 5) and value.startswith(("1", "3")):
        return "BTC", "Base58Check checksum"
    return None


def address_key(address: Address) -> tuple[str, str]:
    value = address.value.lower() if address.network == "EVM" or address.value.lower().startswith("bc1") else address.value
    return address.network, value


def infer_role(value: str, context: str) -> str:
    lowered = context.lower()

    if value.lower() == "0x" + "0" * 40:
        return "null_address"

    # Match the field belonging to this address.
    # A nearby recharge flag does not make it a payment address.
    address = re.escape(value)

    token_field = (
        r'["\x27](?:coin_type|token_address|contract_address|'
        r'lpAddress|lp_address|pair_address)["\x27]\s*:\s*["\x27]'
    )
    if re.search(token_field + address, context, re.I):
        return "possible_contract"

    if re.search(
        r"contract\s*(address)?|token\s*contract|token_address|"
        r"(?:output|input)currency=0x|token-info\?address=0x",
        lowered,
    ):
        return "possible_contract"

    payment_field = (
        r'["\x27](?:deposit_address|payment_address|'
        r'recharge_address|recipient_address)["\x27]\s*:\s*["\x27]'
    )
    if re.search(payment_field + address, context, re.I):
        return "possible_payment"

    # Generic fields in market JSON are not deposit instructions.
    if re.search(r'["\x27]\w+["\x27]\s*:', context):
        return "unknown"

    if re.search(
        r"deposit|recharge|send\s+(?:only|to)|payment\s*address|充值|收款",
        lowered,
    ):
        return "possible_payment"

    return "unknown"


def extract(text: str, source: str, page_url: str, screenshot: str | None = None) -> list[Address]:
    text = unquote(text)
    found = []
    for match in PATTERN.finditer(text):
        value = match.group()
        valid = validate(value)
        if not valid:
            continue
        context = text[max(0, match.start() - 100):match.end() + 100]
        # Role is a transparent heuristic, not a claim about on-chain ownership.
        role = infer_role(value, context)
        found.append(Address(value, *valid, source, page_url, context, role, screenshot))
    return found


def deduplicate(addresses: list[Address]) -> list[Address]:
    result = {}
    for address in addresses:
        # Keep separate sightings: evidence matters even when the wallet repeats.
        key = (*address_key(address), address.page_url, address.source)
        result.setdefault(key, address)
    return list(result.values())
