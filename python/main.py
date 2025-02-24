#!/usr/bin/env python3
import struct, hashlib, binascii
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der


def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def sha256(s):
    return hashlib.sha256(s).digest()

def ripemd160(s):
    h = hashlib.new('ripemd160')
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


version = struct.pack("<I", 1)


prev_txid = bytes.fromhex("00" * 32)
prev_index = struct.pack("<I", 0)


sequence = bytes.fromhex("ffffffff")


witness_script = bytes.fromhex("5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae")
witness_script_hash = sha256(witness_script)

redeem_script_for_scriptSig = bytes([0x00, 0x20]) + witness_script_hash
scriptSig = ser_varint(len(redeem_script_for_scriptSig)) + redeem_script_for_scriptSig


txin = prev_txid + prev_index + scriptSig + sequence


value = struct.pack("<Q", 100000)

dest_script_hash = bytes.fromhex("7f7c9f2e2139af4fa144d9a58c32a7d431c2bfde")
scriptPubKey = bytes([0xa9, 0x14]) + dest_script_hash + bytes([0x87])
txout = value + ser_varint(len(scriptPubKey)) + scriptPubKey


locktime = struct.pack("<I", 0)


def bip143_sighash(tx_version, txin, txout, locktime, scriptCode, amount, input_index=0, sighash=1):
   
    hashPrevouts = hash256(prev_txid + prev_index)
    hashSequence = hash256(sequence)
    hashOutputs = hash256(txout)
    

    outpoint = prev_txid + prev_index

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


privkey1_hex = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"
privkey2_hex = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"

sk1 = SigningKey.from_string(bytes.fromhex(privkey1_hex), curve=SECP256k1)
sk2 = SigningKey.from_string(bytes.fromhex(privkey2_hex), curve=SECP256k1)


sig1_der = sk1.sign_digest(sighash, sigencode=sigencode_der) + b'\x01'
sig2_der = sk2.sign_digest(sighash, sigencode=sigencode_der) + b'\x01'


witness = []
witness.append(b'')         # Dummy item (for off-by-one bug in OP_CHECKMULTISIG)
witness.append(sig1_der)
witness.append(sig2_der)
witness.append(witness_script)  


def serialize_witness(witness):
    result = ser_varint(len(witness))
    for item in witness:
        result += ser_varint(len(item)) + item
    return result

witness_ser = serialize_witness(witness)

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


with open("out.txt", "w") as f:
    f.write(final_tx_hex)

