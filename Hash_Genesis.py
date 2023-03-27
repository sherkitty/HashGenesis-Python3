import hashlib
import binascii
import struct
import array
import os
import time
import sys
import optparse
from construct import *

def main():
    options = get_args()

    algorithm = get_algorithm(options)

    input_script = create_input_script(options.timestamp)
    output_script = create_output_script(options.pubkey)

    # Hash merkle root is the double SHA-256 hash of the transaction(s).
    tx = create_transaction(input_script, output_script, options)
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()

    print_block_info(options, hash_merkle_root)

    block_header = create_block_header(hash_merkle_root, options.time, options.bits, options.nonce)
    genesis_hash, nonce = generate_hash(block_header, algorithm, options.nonce, options.bits)
    announce_found_genesis(genesis_hash, nonce)

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--time", dest="time", default=int(time.time()), 
                type="int", help="the (Unix) time when the genesis block is created")
    parser.add_option("-z", "--timestamp", dest="timestamp", default="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
                type="string", help="the pszTimestamp found in the coinbase of the genesis block")
    parser.add_option("-n", "--nonce", dest="nonce", default=0,
                type="int", help="the first value of the nonce that will be incremented when searching the genesis hash")
    parser.add_option("-a", "--algorithm", dest="algorithm", default="SHA256",
                help="the PoW algorithm: [SHA256|scrypt]")
    parser.add_option("-v", "--version", dest="version", default=1,
                type="int", help="the transaction version")
    parser.add_option("-i", "--num_inputs", dest="num_inputs", default=1,
                type="int", help="the number of transaction inputs")
    (options, args) = parser.parse_args()
    return options

def get_algorithm(options):
    supported_algorithms = ["SHA256", "scrypt", "X11", "X13", "X15"]
    if options.algorithm in supported_algorithms:
        return options.algorithm
    else:
        print("Error: Given algorithm must be one of:", supported_algorithms)

def create_input_script(psz_timestamp):
    psz_prefix = ""
    #use OP_PUSHDATA1 if required
    if len(psz_timestamp) > 76:
        psz_prefix = '4c'

    script_prefix = '04ffff001d0104' + psz_prefix + str(len(psz_timestamp)).encode('hex').decode('utf-8')
    print (script_prefix + psz_timestamp.encode('hex').decode('utf-8'))
    return bytes.fromhex(script_prefix + psz_timestamp.encode('hex').decode('utf-8'))

def create_output_script(pubkey):
    script_len = '41'
    OP_CHECKSIG = 'ac'
    return bytes.fromhex(script_len + pubkey + OP_CHECKSIG)

def create_transaction(input_script, output_script, options):
    transaction = Struct(
        "transaction",
        Bytes("version", 4),
        Byte("num_inputs"),
        StaticField("prev_output", 32),
        UBInt32('prev_out_idx'),
        Byte('input_script_len'),
        Bytes('input_script', len(input_script)),
        UBInt32('sequence'),
        Byte('num_outputs'),
        Bytes('out_value', 8),
        Byte('output_script_len'),
        Bytes('output_script', 0x43),
        UBInt32('locktime')
    )
    return transaction.build(dict(
        version=options.version,
        num_inputs=options.num_inputs,
        prev_output=options.prev_output,
        prev_out_idx=options.prev_out_idx,
        input_script_len=options.input_script_len,
        input_script=input_script,
        sequence=options.sequence,
        num_outputs=options.num_outputs,
        out_value=options.out_value,
        output_script_len=options.output_script_len,
        output_script=output_script,
        locktime=options.locktime
    ))

def get_algorithm(options):
    supported_algorithms = ["SHA256", "scrypt", "X11", "X13", "X15"]
    if options.algorithm in supported_algorithms:
        return options.algorithm
    else:
        print("Error: Given algorithm must be one of:", supported_algorithms)

def create_input_script(psz_timestamp):
    psz_prefix = ""
    #use OP_PUSHDATA1 if required
    if len(psz_timestamp) > 76:
        psz_prefix = '4c'

    script_prefix = '04ffff001d0104' + psz_prefix + str(len(psz_timestamp))
    print(script_prefix + psz_timestamp.hex())
    return bytes.fromhex(script_prefix + psz_timestamp.hex())


def create_output_script(pubkey):
    script_len = '41'
    OP_CHECKSIG = 'ac'
    return bytes.fromhex(script_len + pubkey.hex() + OP_CHECKSIG)


def create_transaction(input_script, output_script, options):
    transaction = Struct("transaction",
        Bytes("version", 4),
        Byte("num_inputs"),
        StaticField("prev_output", 32),
        UBInt32('prev_out_idx'),
        Byte('input_script_len'),
        Bytes('input_script', len(input_script)),
        UBInt32('sequence'),
        Byte('num_outputs'),
        Bytes('out_value', 8),
        Byte('output_script_len'),
        Bytes('output_script',  0x43),
        UBInt32('locktime'))

def create_transaction(input_script, output_script, options):
    tx = transaction.parse('\x00' * (127 + len(input_script)))
    tx.version = struct.pack('<I', 1)
    tx.num_inputs = 1
    tx.prev_output = struct.pack('<qqqq', 0, 0, 0, 0)
    tx.prev_out_idx = 0xFFFFFFFF
    tx.input_script_len = len(input_script)
    tx.input_script = input_script
    tx.sequence = 0xFFFFFFFF
    tx.num_outputs = 1
    tx.out_value = struct.pack('<q', options.value)
    tx.output_script_len = 0x43
    tx.output_script = output_script
    tx.locktime = 0
    return transaction.build(tx)

def create_block_header(hash_merkle_root, time, bits, nonce):
    block_header = struct.Struct("< 4s 32s 32s I I I")
    genesisblock = block_header.pack(
        1,
        b"\x00"*32,
        hash_merkle_root,
        time,
        bits,
        nonce
    )
    return genesisblock


# https://en.bitcoin.it/wiki/Block_hashing_algorithm
def generate_hash(data_block, algorithm, start_nonce, bits):
    print('Searching for genesis hash..')
    nonce = start_nonce
    last_updated = time.time()
    # https://en.bitcoin.it/wiki/Difficulty
    target = (bits & 0xffffff) * 2**(8*((bits >> 24) - 3))
    
def mine_block(data_block, algorithm, target):
    nonce = 0
    last_updated = 0
    while True:
        sha256_hash, header_hash = generate_hashes_from_block(data_block, algorithm)
        last_updated = calculate_hashrate(nonce, last_updated)
        if is_genesis_hash(header_hash, target):
            if algorithm in ["X11", "X13", "X15"]:
                return (header_hash, nonce)
            return (sha256_hash, nonce)
        else:
            nonce += 1
            data_block = data_block[0:len(data_block) - 4] + struct.pack('<I', nonce)

def generate_hashes_from_block(data_block, algorithm):
    sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    if algorithm == 'scrypt':
        header_hash = scrypt.hash(data_block, data_block, 1024, 1, 1, 32)[::-1]
    elif algorithm == 'SHA256':
        header_hash = sha256_hash
    elif algorithm in ['X11', 'X13', 'X15']:
        module_name = algorithm.lower() + '_hash'
        try:
            module = __import__(module_name)
            get_pow_hash = getattr(module, 'getPoWHash')
            header_hash = get_pow_hash(data_block)[::-1]
        except ImportError:
            sys.exit(f"Cannot run {algorithm} algorithm: module {module_name} not found")
    return sha256_hash, header_hash

def is_genesis_hash(header_hash, target):
    return int(header_hash.hex(), 16) < target

def calculate_hashrate(nonce, last_updated):
    now = time.time()
    if now - last_updated >= 1:
        hashrate = nonce / (now - last_updated)
        print(f"Hashrate: {hashrate:.2f} hashes/sec")
        last_updated = now
    return last_updated
    
def main():
    algorithm = "SHA256"
    target = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    data_block = "Some data to hash".encode('utf-8')
    nonce = 0
    last_updated = time.time()
    
    while True:
        sha256_hash, header_hash = generate_hashes_from_block(data_block, algorithm)
        last_updated = calculate_hashrate(nonce, last_updated)
        if is_genesis_hash(header_hash, target):
            if algorithm in ["X11", "X13", "X15"]:
                return (header_hash, nonce)
            return (sha256_hash, nonce)
        else:
            nonce += 1
            data_block = data_block[0:len(data_block) - 4] + struct.pack('<I', nonce)
    
def generate_hashes_from_block(data_block, algorithm):
    sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    header_hash = ""
    if algorithm == 'scrypt':
        header_hash = hashlib.scrypt(data_block, salt=data_block, n=1024, r=1, p=1, dklen=32)[::-1]
    elif algorithm == 'SHA256':
        header_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    elif algorithm == 'X11':
        try:
            import xcoin_hash
        except ImportError:
            sys.exit("Cannot run X11 algorithm: module xcoin_hash not found")
        header_hash = xcoin_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'X13':
        try:
            import x13_hash
        except ImportError:
            sys.exit("Cannot run X13 algorithm: module x13_hash not found")
        header_hash = x13_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'X15':
        try:
            import x15_hash
        except ImportError:
            sys.exit("Cannot run X15 algorithm: module x15_hash not found")
        header_hash = x15_hash.getPoWHash(data_block)[::-1]
    return sha256_hash, header_hash
    
def is_genesis_hash(header_hash, target):
    return int.from_bytes(header_hash, byteorder='big') < target
    
def calculate_hashrate(nonce, last_updated):
    if nonce % 1000000 == 999999:
        now = time.time()
        hashrate = round(1000000 / (now - last_updated))
        generation_time = round(pow(2, 32) / hashrate / 3600, 1)
        sys.stdout.write("\r{} hash/s, estimate: {} h".format(hashrate, generation_time))
        sys.stdout.flush()
        return now
    else:
        return last_updated

def print_block_info(options, hash_merkle_root):
        print("algorithm: "    + options.algorithm)
        print("merkle hash: "  + hash_merkle_root[::-1].encode('hex_codec'))
        print("pszTimestamp: " + options.timestamp)
        print("pubkey: "       + options.pubkey)
        print("time: "         + str(options.time))
        print("bits: "         + str(hex(options.bits)))


def announce_found_genesis(genesis_hash, nonce):
        print("genesis hash found!")
        print("nonce: "        + str(nonce))
        print("genesis hash: " + genesis_hash.encode('hex_codec'))


if __name__ == '__main__':
    main()    
    
    
    
