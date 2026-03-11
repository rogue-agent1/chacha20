#!/usr/bin/env python3
"""chacha20 - ChaCha20 stream cipher (RFC 8439).

Usage: python chacha20.py <message> [--key HEX] [--nonce HEX]
"""
import sys, struct

def _quarter_round(s, a, b, c, d):
    M = 0xFFFFFFFF
    def rotl32(v, n): return ((v << n) | (v >> (32-n))) & M
    s[a] = (s[a]+s[b])&M; s[d] ^= s[a]; s[d] = rotl32(s[d],16)
    s[c] = (s[c]+s[d])&M; s[b] ^= s[c]; s[b] = rotl32(s[b],12)
    s[a] = (s[a]+s[b])&M; s[d] ^= s[a]; s[d] = rotl32(s[d],8)
    s[c] = (s[c]+s[d])&M; s[b] ^= s[c]; s[b] = rotl32(s[b],7)

def chacha20_block(key, counter, nonce):
    assert len(key)==32 and len(nonce)==12
    constants = b'expand 32-byte k'
    s = list(struct.unpack('<4I', constants))
    s += list(struct.unpack('<8I', key))
    s += [counter]
    s += list(struct.unpack('<3I', nonce))
    working = list(s)
    for _ in range(10):  # 20 rounds = 10 double-rounds
        _quarter_round(working,0,4,8,12)
        _quarter_round(working,1,5,9,13)
        _quarter_round(working,2,6,10,14)
        _quarter_round(working,3,7,11,15)
        _quarter_round(working,0,5,10,15)
        _quarter_round(working,1,6,11,12)
        _quarter_round(working,2,7,8,13)
        _quarter_round(working,3,4,9,14)
    out = [(working[i]+s[i])&0xFFFFFFFF for i in range(16)]
    return struct.pack('<16I', *out)

def chacha20_encrypt(key, nonce, plaintext, counter=1):
    out = bytearray()
    for i in range(0, len(plaintext), 64):
        block = chacha20_block(key, counter + i//64, nonce)
        chunk = plaintext[i:i+64]
        out.extend(b ^ k for b, k in zip(chunk, block))
    return bytes(out)

def main():
    if len(sys.argv) < 2:
        # Run test vector from RFC 8439
        print("ChaCha20 — RFC 8439 test vector:\n")
        key = bytes(range(32))  # 00010203...1f
        nonce = bytes([0,0,0,0,0,0,0,0x4a,0,0,0,0])
        pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        ct = chacha20_encrypt(key, nonce, pt)
        print(f"Key:        {key.hex()}")
        print(f"Nonce:      {nonce.hex()}")
        print(f"Plaintext:  {pt.decode()}")
        print(f"Ciphertext: {ct.hex()[:80]}...")
        # Decrypt (stream cipher: encrypt=decrypt)
        dt = chacha20_encrypt(key, nonce, ct)
        print(f"Decrypted:  {dt.decode()}")
        assert dt == pt, "Decryption failed!"
        print("\n✓ Encrypt/decrypt roundtrip OK")
        return

    msg = sys.argv[1].encode()
    key = bytes.fromhex(sys.argv[sys.argv.index("--key")+1]) if "--key" in sys.argv else bytes(range(32))
    nonce = bytes.fromhex(sys.argv[sys.argv.index("--nonce")+1]) if "--nonce" in sys.argv else b'\x00'*12
    ct = chacha20_encrypt(key, nonce, msg)
    print(f"Ciphertext: {ct.hex()}")
    dt = chacha20_encrypt(key, nonce, ct)
    print(f"Decrypted:  {dt.decode()}")

if __name__ == "__main__":
    main()
