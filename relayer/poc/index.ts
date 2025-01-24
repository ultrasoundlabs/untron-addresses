// Import necessary libraries
const dotenv = require('dotenv');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { ec: EC } = require('elliptic');
const keccak256 = require('keccak');
const bs58check = require('bs58check');

// Load environment variables from .env file
dotenv.config();

// Initialize elliptic curve
const ec = new EC('secp256k1');

// Function to derive path from entropy address
function derivePath(entropyAddress: string) {
    // Remove '0x' prefix if present
    if (entropyAddress.startsWith('0x') || entropyAddress.startsWith('0X')) {
        entropyAddress = entropyAddress.slice(2);
    }

    // Convert entropy address to bytes
    const entropyBytes = Buffer.from(entropyAddress, 'hex');

    // Calculate indices from each 2 bytes of entropy
    const indices: string[] = [];
    for (let i = 0; i < entropyBytes.length; i += 2) {
        const index = entropyBytes.readUInt16BE(i);
        indices.push(index.toString());
    }

    // Join indices with '/' to create path
    return `m/${indices.join('/')}`;
}

// Main logic
(async () => {
    // Load xpub from environment variables
    const xpub = process.env.ROOT_XPUB;

    // Check if xpub is provided
    if (!xpub) {
        console.error('Error: ROOT_XPUB not found in environment variables.');
        return;
    }

    // Example entropy address in the EVM format
    const entropyAddress = '0x1234567890123456789012345678901234567890';
    console.log(`Entropy address: ${entropyAddress}`);

    // Get derivation path from the EVM entropy address
    const path = derivePath(entropyAddress);
    console.log(`Derivation path: ${path}`);

    // Load BIP32 root key from xpub
    const bip32 = BIP32Factory(ecc);
    const rootNode = bip32.fromBase58(xpub);

    // Derive the child node using the path
    const childNode = rootNode.derivePath(path);

    // Get the child public key
    const childPublicKey = childNode.publicKey;

    // Display the child public key in hex format
    console.log(`Child public key: ${childPublicKey.toString('hex')}`);

    // Create an EC key pair from the compressed public key
    const key = ec.keyFromPublic(childPublicKey, 'hex');

    // Get the uncompressed public key
    const publicKey = key.getPublic();
    const uncompressedPublicKey = Buffer.from(publicKey.encode('hex', false), 'hex').slice(1);

    console.log("uncompressedPublicKey", uncompressedPublicKey);

    // Take keccak256 hash of the uncompressed public key and get the last 20 bytes
    const keccakHash = keccak256('keccak256').update(uncompressedPublicKey).digest();
    const addressHash = keccakHash.slice(-20);

    // Prefix the address with 0x41 for Tron addresses
    const tronAddressBytes = Buffer.concat([Buffer.from([0x41]), addressHash]);

    console.log("tronAddressBytes", tronAddressBytes);

    // Encode the address in Base58Check format
    const tronAddress = bs58check.default.encode(tronAddressBytes);

    // Display the derived Tron address
    console.log(`Child Tron address: ${tronAddress}`);
})();
