#!/usr/bin/env python3
import struct, hashlib
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der
from Crypto.Hash import RIPEMD160

# ----- Helper Functions -----
def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def sha256(s):
    return hashlib.sha256(s).digest()

def ripemd160(s):
    return RIPEMD160.new(sha256(s)).digest()

def hash160(s):
    return ripemd160(sha256(s))

def ser_varint(i):
    if i < 0xfd:
        return struct.pack("B", i)
    elif i <= 0xffff:
        return b'\xfd' + struct.pack("<H", i)
    elif i <= 0xffffffff:
        return b'\xfe' + struct.pack("<I", i)
    else:
        return b'\xff' + struct.pack("<Q", i)

def base58_decode(s):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = sum(alphabet.index(char) * (58 ** i) for i, char in enumerate(reversed(s)))
    return num.to_bytes(25, "big")


version = struct.pack("<I", 1)
prev_txid = bytes(32)  # all-zero txid
prev_index = struct.pack("<I", 0)
sequence = bytes.fromhex("ffffffff")


witness_script = bytes.fromhex(
    "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b"
    "21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae"
)


witness_program = bytes.fromhex("00") + bytes([32]) + sha256(witness_script)


dest_script_hash = base58_decode("325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF")[1:21]
scriptPubKey = bytes([0xa9, 0x14]) + dest_script_hash + bytes([0x87])
txout = struct.pack("<Q", 100000) + ser_varint(len(scriptPubKey)) + scriptPubKey
locktime = struct.pack("<I", 0)


def segwit_sighash():
 
    input_value = 100000
    hash_prevouts = hash256(prev_txid + prev_index)
    hash_sequence = hash256(sequence)
    hash_outputs = hash256(txout)

    scriptCode = ser_varint(len(witness_script)) + witness_script
    sighash_type = struct.pack("<I", 1)  
    preimage = (
        version +
        hash_prevouts +
        hash_sequence +
        prev_txid + prev_index +
        scriptCode +
        struct.pack("<Q", input_value) +
        sequence +
        hash_outputs +
        locktime +
        sighash_type
    )
    return hash256(preimage)

sighash = segwit_sighash()


privkeys = [
    "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf",
    "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"
]

signatures = [
    SigningKey.from_string(bytes.fromhex(pk), curve=SECP256k1).sign_digest(sighash, sigencode=sigencode_der) + b'\x01'
    for pk in privkeys
]

def push_data(data):
    return ser_varint(len(data)) + data


scriptSig = push_data(witness_program)


txin = prev_txid + prev_index + ser_varint(len(scriptSig)) + scriptSig + sequence


witness_items = [b"", signatures[0], signatures[1], witness_script]
witness = ser_varint(len(witness_items)) + b"".join(push_data(item) for item in witness_items)

tx_final = (
    version +
    b'\x00\x01' +
    ser_varint(1) + txin +
    ser_varint(1) + txout +
    witness +
    locktime
)


with open("out.txt", "w") as f:
    f.write(tx_final.hex())
