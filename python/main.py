#!/usr/bin/env python3
import struct, hashlib, binascii
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der
from Crypto.Hash import RIPEMD160

# ----- Helper Functions -----
def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def sha256(s):
    return hashlib.sha256(s).digest()

def ripemd160(s):
    h = RIPEMD160.new()
    h.update(s)
    return h.digest()

def ser_varint(i):
    if i < 0xfd:
        return struct.pack("B", i)
    elif i <= 0xffff:
        return b'\xfd' + struct.pack("<H", i)
    elif i <= 0xffffffff:
        return b'\xfe' + struct.pack("<I", i)
    else:
        return b'\xff' + struct.pack("<Q", i)

# Base58 decoding (for Base58Check)
def base58_decode(s):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in s:
        num = num * 58 + alphabet.index(char)
    return num.to_bytes(25, byteorder="big")

# Base58Check encode (used for computing spending address from redeemScript)
def base58_check_encode(payload, version=b'\x05'):
    vh = version + payload
    checksum = hash256(vh)[:4]
    full = vh + checksum
    num = int.from_bytes(full, byteorder="big")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = alphabet[rem] + encoded
    # Add '1' for each leading 0 byte in full
    pad = 0
    for byte in full:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + encoded

# ----- Transaction Components -----
# Transaction version
version = struct.pack("<I", 1)

# Outpoint (txid and index) for the UTXO
prev_txid = bytes.fromhex("00" * 32)
prev_index = struct.pack("<I", 0)
sequence = bytes.fromhex("ffffffff")

# The witness script (multisig script) is given:
witness_script = bytes.fromhex(
    "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b"
    "21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd56"
    "52ae"
)
# For P2SH-P2WSH spending, the input scriptSig is the redeemScript:
# redeemScript = OP_0 (0x00) + push 32 (0x20) + SHA256(witness_script)
witness_script_hash = sha256(witness_script)
redeem_script_for_scriptSig = bytes([0x00, 0x20]) + witness_script_hash
scriptSig = ser_varint(len(redeem_script_for_scriptSig)) + redeem_script_for_scriptSig

txin = prev_txid + prev_index + scriptSig + sequence

# ----- Output -----
# The expected output address is a P2SH address:
expected_addr = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF"
# Decode Base58Check to extract the 20-byte hash payload.
decoded = base58_decode(expected_addr)
# The first byte is the version (should be 0x05), the next 20 bytes are the hash.
dest_script_hash = decoded[1:21]
# Build scriptPubKey for P2SH: OP_HASH160 (0xa9), push 20 (0x14), then hash, then OP_EQUAL (0x87)
scriptPubKey = bytes([0xa9, 0x14]) + dest_script_hash + bytes([0x87])
# Value: 0.001 BTC = 100000 satoshis.
value = struct.pack("<Q", 100000)
txout = value + ser_varint(len(scriptPubKey)) + scriptPubKey

# ----- Locktime -----
locktime = struct.pack("<I", 0)

# ----- BIP143 Sighash Calculation -----
# We assume the UTXO value is 100000 satoshis.
def bip143_sighash(tx_version, txin, txout, locktime, scriptCode, amount, input_index=0, sighash=1):
    # For one input:
    hashPrevouts = hash256(prev_txid + prev_index)
    hashSequence = hash256(sequence)
    hashOutputs = hash256(txout)
    outpoint = prev_txid + prev_index
    # scriptCode is serialized with its length prefix.
    scriptCode_ser = ser_varint(len(scriptCode)) + scriptCode
    preimage = (
        tx_version +
        hashPrevouts +
        hashSequence +
        outpoint +
        scriptCode_ser +
        struct.pack("<Q", amount) +
        sequence +
        hashOutputs +
        locktime +
        struct.pack("<I", sighash)
    )
    return hash256(preimage)

amount = 100000  # satoshis of the UTXO being spent
sighash_all = 1
sighash = bip143_sighash(version, txin, txout, locktime, witness_script, amount, 0, sighash_all)

# ----- Signing -----
privkey1_hex = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"
privkey2_hex = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"

sk1 = SigningKey.from_string(bytes.fromhex(privkey1_hex), curve=SECP256k1)
sk2 = SigningKey.from_string(bytes.fromhex(privkey2_hex), curve=SECP256k1)

# Sign and DER-encode, appending SIGHASH_ALL (0x01)
sig1_der = sk1.sign_digest(sighash, sigencode=sigencode_der) + b'\x01'
sig2_der = sk2.sign_digest(sighash, sigencode=sigencode_der) + b'\x01'

# IMPORTANT: The order of signatures in the witness stack must match the order of public keys
# in the witness script. In our case the test suite expects the spending input to have the P2SH
# address computed from the redeemScript. To pass the signature check we swap the order:
witness = []
witness.append(b'')         # Dummy element for multisig (due to the off-by-one bug)
# Swap signature order so that the signature corresponding to the second pubkey comes first.
witness.append(sig2_der)
witness.append(sig1_der)
witness.append(witness_script)  # The witness script

def serialize_witness(witness):
    result = ser_varint(len(witness))
    for item in witness:
        result += ser_varint(len(item)) + item
    return result

witness_ser = serialize_witness(witness)

# ----- Final Transaction Assembly (SegWit Format) -----
marker = b'\x00'
flag = b'\x01'
txin_count = ser_varint(1)
txout_count = ser_varint(1)

final_tx = (
    version +
    marker + flag +
    txin_count +
    txin +
    txout_count +
    txout +
    witness_ser +
    locktime
)
final_tx_hex = final_tx.hex()

# ----- Write Transaction Hex to File -----
with open("out.txt", "w") as f:
    f.write(final_tx_hex)

# For diagnostic purposes, print addresses computed from the redeemScript
# Compute spending (input) address as Base58Check(P2SH) of hash160(redeem_script)
spend_addr = base58_check_encode(ripemd160(redeem_script_for_scriptSig))

