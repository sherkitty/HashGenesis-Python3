import hashlib
import time

def hash_block(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward, target_difficulty):
    block = str(nVersion) + pszTimestamp + str(genesisOutputScript) + str(nTime) + str(nBits) + str(nNonce) + str(genesisReward)
    block_hash = hashlib.sha256(hashlib.sha256(block.encode('utf-8')).digest()).digest()
    kilohashes_per_second = 0
    
    while int.from_bytes(block_hash, 'big') > target_difficulty:
        nNonce += 1
        block = str(nVersion) + pszTimestamp + str(genesisOutputScript) + str(nTime) + str(nBits) + str(nNonce) + str(genesisReward)
        block_hash = hashlib.sha256(hashlib.sha256(block.encode('utf-8')).digest()).digest()
        kilohashes_per_second += 1
        if kilohashes_per_second % 1000 == 0:
            print(f"{kilohashes_per_second / 1000} KH/s")
    
    valid_block = f"{nVersion},{pszTimestamp},{genesisOutputScript},{nTime},{nBits},{nNonce},{genesisReward},{block_hash.hex()}"
    with open("Gen_file.txt", "w") as f:
        f.write(valid_block)
    return valid_block

if __name__ == '__main__':
    pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    genesisOutputScript = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f,OP_CHECKSIG"
    nTime = 1231006505
    nNonce = 0
    nBits = 0x1d00ffff
    nVersion = 1
    genesisReward = 0x00a0860100000000
    target_difficulty = int("00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

    start_time = time.time()
    valid_block = hash_block(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward, target_difficulty)
    end_time = time.time()
    print(f"Time taken: {end_time - start_time} seconds")
