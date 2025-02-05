import hashlib
import hmac
import os
import time
import base58
import ecdsa
from typing import Tuple, List
from dotenv import load_dotenv
from requests import Session
from web3 import Web3
from base58 import b58encode_check
from tronpy import Tron
from tronpy.providers import HTTPProvider
from tronpy.keys import PrivateKey

load_dotenv()

client = Tron(
    provider=HTTPProvider(
        "https://api.trongrid.io/jsonrpc", api_key=os.getenv("TRONGRID_API_KEY")
    )
)

private_key = PrivateKey(bytes.fromhex(os.getenv("TRON_PRIVATE_KEY").lstrip("0x")))
relayer_address = private_key.public_key.to_base58check_address()
sunswap_v2 = client.get_contract("TXF1xDbVGdxFGbovmmmXvBGu8ZiE3Lq4mR")


class BIP32:
    def __init__(self, xprv: str):
        # Decode xprv
        decoded = base58.b58decode_check(xprv)

        # Extract components from decoded xprv
        self.version = decoded[:4]
        self.depth = decoded[4]
        self.parent_fingerprint = decoded[5:9]
        self.child_number = int.from_bytes(decoded[9:13], "big")
        self.chain_code = decoded[13:45]
        self.private_key = decoded[46:78]  # Skip version byte

        # Initialize secp256k1 curve
        self.curve = ecdsa.SECP256k1

        # Derive public key from private key
        signing_key = ecdsa.SigningKey.from_string(self.private_key, curve=self.curve)
        verifying_key = signing_key.get_verifying_key()
        point = verifying_key.pubkey.point

        # Create compressed public key
        self.public_key = b"\x03" if point.y() % 2 else b"\x02"
        self.public_key += point.x().to_bytes(32, "big")

        # Create xpub
        xpub_bytes = (
            b"\x04\x88\xb2\x1e"  # Version bytes for xpub
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + self.public_key
        )
        self.xpub = base58.b58encode_check(xpub_bytes).decode()

    def _parse_path(self, path: str) -> List[int]:
        """Convert BIP32 path string to index array"""
        if path.startswith("m/"):
            path = path[2:]
        return [
            int(i) if "'" not in i else int(i[:-1]) + 0x80000000
            for i in path.split("/")
            if i
        ]

    def _ckd_prv(
        self, parent_prv_key: bytes, parent_chain_code: bytes, i: int
    ) -> Tuple[bytes, bytes]:
        """Derive child private key from parent private key"""
        # Data to HMAC
        if i & 0x80000000:  # Hardened child
            data = b"\x00" + parent_prv_key + i.to_bytes(4, "big")
        else:  # Normal child
            # Get parent pubkey point
            parent_pub_key = (
                ecdsa.SigningKey.from_string(parent_prv_key, curve=self.curve)
                .get_verifying_key()
                .to_string("compressed")
            )
            data = parent_pub_key + i.to_bytes(4, "big")

        # Calculate I
        I = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]

        # Calculate child private key
        IL_int = int.from_bytes(IL, "big")
        if IL_int >= self.curve.order:
            raise ValueError("IL is greater than or equal to curve order")

        child_prv_key = (
            IL_int + int.from_bytes(parent_prv_key, "big")
        ) % self.curve.order
        child_prv_key = child_prv_key.to_bytes(32, "big")

        return child_prv_key, IR

    def _ckd_pub(
        self, parent_pub_key: bytes, parent_chain_code: bytes, i: int
    ) -> Tuple[bytes, bytes]:
        """Derive child public key from parent public key"""
        if i & 0x80000000:
            raise ValueError("Cannot derive hardened child from public key")

        # Data to HMAC
        data = parent_pub_key + i.to_bytes(4, "big")

        # Calculate I
        I = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]

        # Convert IL to point and add to parent pubkey point
        IL_int = int.from_bytes(IL, "big")
        if IL_int >= self.curve.order:
            raise ValueError("IL is greater than or equal to curve order")

        point = IL_int * self.curve.generator
        parent_point = ecdsa.VerifyingKey.from_string(parent_pub_key, curve=self.curve)
        parent_point = parent_point.pubkey.point

        # Add points and get child public key
        child_point = point + parent_point
        child_pub_key = b"\x03" if child_point.y() % 2 else b"\x02"
        child_pub_key += child_point.x().to_bytes(32, "big")

        return child_pub_key, IR

    def derive_child_privkey(self, path: str) -> str:
        """Derive child private key from xprv and path"""
        indices = self._parse_path(path)
        derived_prv_key = self.private_key
        derived_chain_code = self.chain_code

        for child_index in indices:
            derived_prv_key, derived_chain_code = self._ckd_prv(
                derived_prv_key, derived_chain_code, child_index
            )

        return derived_prv_key.hex()

    def derive_child_pubkey(self, path: str) -> str:
        """Derive child public key from xpub and path"""
        indices = self._parse_path(path)
        derived_pub_key = self.public_key
        derived_chain_code = self.chain_code

        for child_index in indices:
            derived_pub_key, derived_chain_code = self._ckd_pub(
                derived_pub_key, derived_chain_code, child_index
            )

        return derived_pub_key.hex()

    def derive_tron_address(self, path: str) -> str:
        """Derive Tron address from child public key"""
        # Get the public key in hex
        pubkey_hex = self.derive_child_pubkey(path)

        # Convert to uncompressed public key bytes (remove compression prefix)
        pubkey_point = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(pubkey_hex), curve=self.curve
        ).pubkey.point

        # Get full uncompressed public key bytes (64 bytes for x and y coordinates)
        pubkey_bytes = pubkey_point.x().to_bytes(32, "big") + pubkey_point.y().to_bytes(
            32, "big"
        )

        print("pubkey_bytes", pubkey_bytes.hex())

        # Take keccak256 hash and get last 20 bytes for address
        keccak = Web3.keccak(pubkey_bytes)
        address = keccak[-20:]

        print("address", address.hex())

        # Return address in Tron format
        return b58encode_check(b"\x41" + address).decode()


def derive_path(entropy_address: str) -> str:
    """Derive derivation path from entropy address"""
    # Convert entropy address to bytes
    entropy_bytes = bytes.fromhex(entropy_address[2:])

    # Calculate indices from each 2 bytes of entropy
    indices = []
    for i in range(0, len(entropy_bytes), 2):
        index = int.from_bytes(entropy_bytes[i : i + 2], "big")
        indices.append(str(index))

    # Join indices with / to create path
    return f"m/{'/'.join(indices)}"

# Lends energy to the address using feee.io API V3
def lend_energy(to: str, amount: int):
    session = Session()
    session.headers["key"] = os.getenv("FEEE_API_KEY")
    session.headers["Content-Type"] = "application/json"

    # Create order using V3 API
    payload = {
        "resource_type": 1,  # 1 for energy
        "receive_address": to,
        "resource_value": amount
    }

    with session.post("https://feee.io/open/v3/order/create", json=payload) as resp:
        result = resp.json()
        print(result)

        if result["code"] != 0:
            print("Failed to create order:", result["msg"])
            return False

        # V3 API sends energy within 3-6 seconds if successful
        # No need to poll status since rental time is fixed at 5 minutes
        if result["data"]["business_status"] >= 1:
            print("Energy rented successfully")
            time.sleep(10)
            return True
        else:
            print("Failed to rent energy")
            return False


# Sends 10 TRX to the address from the relayer
def supply_address(address: str):
    txn = (
        client.trx.transfer(relayer_address, address, 10_000_000)
        .with_owner(relayer_address)
        .fee_limit(2_000_000) # in case not initialized yet
        .build()
        .sign(private_key)
    )
    receipt = txn.broadcast().wait()
    print(f"[Tron] Supply tx result: {receipt}")


# Main logic
if __name__ == "__main__":
    # Import xprv from .env
    xprv = os.getenv("ROOT_XPRV")

    # Example entropy address in the EVM format
    entropy_address = "0x93F296B84f7442Cc63ECD25C1E076d084f136A5E"
    print(f"Entropy address: {entropy_address}")

    # Get derivation path from the EVM entropy address
    path = derive_path(entropy_address)
    print(f"Derivation path: {path}")

    bip32 = BIP32(xprv)
    print(f"Root public key (xpub): {bip32.xpub}")
    child_pubkey = bip32.derive_child_pubkey(path)
    print(f"Child public key: {child_pubkey}")
    child_privkey = bip32.derive_child_privkey(path)
    print(f"Child private key: {child_privkey}")
    child_tron_address = bip32.derive_tron_address(path)
    print(f"Child Tron address: {child_tron_address}")

    exit()

    child_signer = PrivateKey(bytes.fromhex(child_privkey))

    usdt = client.get_contract("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
    balance = usdt.functions.balanceOf(child_tron_address)
    if balance == 0:
        print("Balance is 0, exiting")
        exit()
    
    try:
        trx_balance = client.get_account_balance(child_tron_address)
    except Exception:
        trx_balance = 0
    
    print(f"TRX balance: {trx_balance}")
    
    if trx_balance < 1: # 1 TRX is enough for the approval given the rental
        supply_address(child_tron_address)
    
    allowance = usdt.functions.allowance(child_tron_address, sunswap_v2.address)
    if allowance == 0:
        print("Allowance is 0, setting max approval")

        lend_energy(child_tron_address, 101000) # enough for the approval and swap

        txn = (
            usdt.functions.approve(sunswap_v2.address, 2**256 - 1)
                .with_owner(child_tron_address)
                .fee_limit(100_000_000)
                .build()
                .sign(child_signer)
        )
        receipt = txn.broadcast().wait()
        print(f"[Tron] Approve tx result: {receipt}")
    else:
        print("Allowance is already set")

    txn = (
        sunswap_v2.functions.swapExactTokensForTokens(
            balance,
            1,  # we know that there'd be no slippage
            [
                "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                "TPXxtMtQg95VX8JRCiQ5SXqSeHjuNaMsxi"
            ],
            relayer_address, # swap new USDT into wrapped tokens and send them to the relayer
            9999999999,  # large deadline
        )
        .with_owner(child_tron_address)
        .fee_limit(2_000_000)
        .build()
        .sign(child_signer)
    )
    receipt = txn.broadcast().wait()
    print(f"[Tron] Swap tx result: {receipt}")
