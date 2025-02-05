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
from sqlite3 import connect
from threading import Thread, Event
from queue import Queue
import schedule
from datetime import datetime
from flask import Flask, request, jsonify, redirect

load_dotenv()

# Initialize monitor as None - will be set in __main__
monitor = None

app = Flask(__name__)

@app.route('/')
def root():
    return redirect('https://untron.eth.limo', code=301)

@app.route('/api/addresses/inform')
def add_new_address():
    if monitor is None:
        return jsonify({"error": "Monitor not initialized"}), 500
        
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "address parameter is required"}), 400
    if not address.startswith('0x') or len(address) != 42:
        return jsonify({"error": "invalid address format"}), 400
    
    try:
        bytes.fromhex(address[2:])
    except ValueError:
        return jsonify({"error": "invalid address format"}), 400
    
    try:
        # Derive the Tron address
        path = derive_path(address)
        bip32 = BIP32(monitor.xprv)
        tron_address = bip32.derive_tron_address(path)
        
        # Check if address already exists in DB
        with connect(DB_PATH) as conn:
            cursor = conn.execute("SELECT address FROM entropy_addresses WHERE address = ?", (address,))
            if cursor.fetchone():
                return jsonify({
                    "success": True, 
                    "message": f"Address {address} is already being monitored",
                    "tron_address": tron_address
                }), 200
        
        monitor.add_address(address)
        return jsonify({
            "success": True, 
            "message": f"Added {address} to monitoring",
            "tron_address": tron_address
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Database setup
DB_PATH = os.getenv("DB_PATH", "addresses.db")

def init_db():
    with connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entropy_addresses (
                address TEXT PRIMARY KEY,
                processing BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked TIMESTAMP
            )
        """)

init_db()

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
        ii = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
        IL, IR = ii[:32], ii[32:]

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
        ii = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
        IL, IR = ii[:32], ii[32:]

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

        # Take keccak256 hash and get last 20 bytes for address
        keccak = Web3.keccak(pubkey_bytes)
        address = keccak[-20:]

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


class AddressMonitor:
    def __init__(self, xprv: str):
        self.xprv = xprv
        self.stop_event = Event()
        self.queue = Queue()
        self.active_monitors = {}  # Track active monitoring threads
        self.entropy_addresses = {}  # Track entropy addresses for each monitored address
        
        # Reset any stuck addresses from previous runs
        with connect(DB_PATH) as conn:
            conn.execute("""
                UPDATE entropy_addresses 
                SET processing = FALSE 
                WHERE processing = TRUE
            """)
        
        # Start scheduler thread
        Thread(target=self._schedule_checks, daemon=True).start()

    def add_address(self, entropy_address: str):
        with connect(DB_PATH) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO entropy_addresses (address) 
                VALUES (?)
            """, (entropy_address,))
        # Store the entropy address for later use
        path = derive_path(entropy_address)
        bip32 = BIP32(self.xprv)
        child_tron_address = bip32.derive_tron_address(path)
        self.entropy_addresses[child_tron_address] = entropy_address

    def _get_pending_addresses(self):
        with connect(DB_PATH) as conn:
            # Enable datetime functions
            conn.execute("PRAGMA datetime_functions = ON")
            
            cursor = conn.execute("""
                UPDATE entropy_addresses 
                SET processing = TRUE 
                WHERE address IN (
                    SELECT address 
                    FROM entropy_addresses 
                    WHERE processing = FALSE 
                        AND (last_checked IS NULL 
                             OR strftime('%s', 'now') - strftime('%s', last_checked) >= 5)
                    ORDER BY created_at 
                    LIMIT 100
                )
                RETURNING address
            """)
            return [row[0] for row in cursor.fetchall()]

    def _schedule_checks(self):
        schedule.every(5).seconds.do(self._start_new_monitors)
        while not self.stop_event.is_set():
            schedule.run_pending()
            time.sleep(1)

    def _enqueue_addresses(self):
        # Debug: show all addresses in DB
        with connect(DB_PATH) as conn:
            cursor = conn.execute("""
                SELECT address, processing, last_checked 
                FROM entropy_addresses
                ORDER BY created_at
            """)
            rows = cursor.fetchall()
            if rows:
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Current DB state:")
                for row in rows:
                    print(f"  Address: {row[0][:10]}...{row[0][-8:]}, Processing: {row[1]}, Last checked: {row[2]}")
                print()
        return self._get_pending_addresses()

    def _start_new_monitors(self):
        # Clean up finished threads
        self.active_monitors = {addr: thread for addr, thread in self.active_monitors.items() 
                              if thread.is_alive()}
        
        # Get new addresses to monitor
        addresses = self._enqueue_addresses()
        if addresses:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(addresses)} addresses to monitor")
            
        # Start new monitoring threads for addresses not already being monitored
        for address in addresses:
            if address not in self.active_monitors:
                thread = Thread(target=self._monitor_address, args=(address,), daemon=True)
                thread.start()
                self.active_monitors[address] = thread

    def _monitor_address(self, entropy_address: str):
        path = derive_path(entropy_address)
        bip32 = BIP32(self.xprv)
        
        try:
            child_tron_address = bip32.derive_tron_address(path)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Started monitoring {entropy_address[:10]}...{entropy_address[-8:]} -> {child_tron_address}")
            usdt = client.get_contract("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
            
            while not self.stop_event.is_set():
                try:
                    balance = usdt.functions.balanceOf(child_tron_address)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Balance check: {balance} USDT @ {child_tron_address[:10]}...{child_tron_address[-8:]}")
                    if balance > 0:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Found positive balance, processing...")
                        self._handle_balance(child_tron_address, bip32, path, entropy_address)
                        # Successfully handled balance, stop monitoring this address
                        return
                    
                    time.sleep(5)  # Check balance every 5 seconds
                    
                except Exception as e:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Error checking {child_tron_address[:10]}...{child_tron_address[-8:]}: {e}")
                    time.sleep(5)
        
        finally:
            # Only mark as not processing if we're stopping monitoring
            # (either due to successful balance handling or stop event)
            with connect(DB_PATH) as conn:
                conn.execute("""
                    UPDATE entropy_addresses 
                    SET processing = FALSE,
                        last_checked = CURRENT_TIMESTAMP
                    WHERE address = ?
                """, (entropy_address,))

    def _handle_balance(self, child_tron_address: str, bip32: BIP32, path: str, entropy_address: str):
        child_privkey = bip32.derive_child_privkey(path)
        child_signer = PrivateKey(bytes.fromhex(child_privkey))
        
        usdt = client.get_contract("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
        balance = usdt.functions.balanceOf(child_tron_address)
        if balance == 0:
            print("Balance is 0, skipping")
            return

        try:
            trx_balance = client.get_account_balance(child_tron_address)
            fee = 500000 # 0.5 USDT
        except Exception:
            trx_balance = 0
            fee = 2000000 # 2 USDT

        # Initialize Web3 for EVM chain first
        w3 = Web3(Web3.HTTPProvider(os.getenv("EVM_RPC_URL")))
        evm_account = w3.eth.account.from_key(os.getenv("EVM_PRIVATE_KEY"))

        # Get USDT contract on EVM chain
        usdt_abi = [
            {
                "constant": False,
                "inputs": [
                    {"name": "_to", "type": "address"},
                    {"name": "_value", "type": "uint256"}
                ],
                "name": "transfer",
                "outputs": [{"name": "", "type": "bool"}],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        usdt_contract = w3.eth.contract(
            address=w3.to_checksum_address(os.getenv("USDT_CONTRACT_ADDRESS")), 
            abi=usdt_abi
        )

        # Build and send the EVM transaction first
        try:
            nonce = w3.eth.get_transaction_count(evm_account.address)
            transfer_txn = usdt_contract.functions.transfer(
                w3.to_checksum_address(entropy_address),
                balance - fee  # Same amount as received on Tron minus the fee
            ).build_transaction({
                'chainId': w3.eth.chain_id,
                'gas': 100000,  # Standard ERC20 transfer gas
                'gasPrice': w3.eth.gas_price,
                'nonce': nonce,
            })

            # Sign and send the transaction
            signed_txn = w3.eth.account.sign_transaction(transfer_txn, evm_account.key)
            tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"[EVM] USDT transfer tx result: {tx_receipt}")
            
            if tx_receipt.status != 1:
                raise Exception("EVM transfer failed")
                
        except Exception as e:
            print(f"[EVM] Failed to send USDT: {str(e)}")
            return  # Don't proceed with Tron side if EVM transfer fails
        
        print("[Tron] Processing Tron side after successful EVM transfer")
        print(f"TRX balance: {trx_balance}")
        
        if trx_balance < 1:  # 1 TRX is enough for the approval given the rental
            supply_address(child_tron_address)
        
        allowance = usdt.functions.allowance(child_tron_address, sunswap_v2.address)
        if allowance == 0:
            print("Allowance is 0, setting max approval")

            lend_energy(child_tron_address, 101000)  # enough for the approval and swap

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
                relayer_address,  # swap new USDT into wrapped tokens and send them to the relayer
                9999999999,  # large deadline
            )
            .with_owner(child_tron_address)
            .fee_limit(2_000_000)
            .build()
            .sign(child_signer)
        )
        receipt = txn.broadcast().wait()
        print(f"[Tron] Swap tx result: {receipt}")

    def stop(self):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Shutting down monitor...")
        self.stop_event.set()
        
        # Wait for all monitoring threads to finish
        for thread in self.active_monitors.values():
            thread.join(timeout=5)

# Main logic
if __name__ == "__main__":
    # Import xprv from .env
    xprv = os.getenv("ROOT_XPRV")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting address monitor...")
    monitor = AddressMonitor(xprv)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Monitor initialized")
    
    try:
        # Run Flask app
        app.run(host='0.0.0.0', port=8453)
    except KeyboardInterrupt:
        monitor.stop()
