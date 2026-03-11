#!/usr/bin/env python3
"""ChaCha20 stream cipher — pure Python implementation."""
import struct, sys

def _quarter_round(state, a, b, c, d):
    M = 0xFFFFFFFF
    state[a] = (state[a] + state[b]) & M; state[d] ^= state[a]; state[d] = ((state[d] << 16) | (state[d] >> 16)) & M
    state[c] = (state[c] + state[d]) & M; state[b] ^= state[c]; state[b] = ((state[b] << 12) | (state[b] >> 20)) & M
    state[a] = (state[a] + state[b]) & M; state[d] ^= state[a]; state[d] = ((state[d] << 8) | (state[d] >> 24)) & M
    state[c] = (state[c] + state[d]) & M; state[b] ^= state[c]; state[b] = ((state[b] << 7) | (state[b] >> 25)) & M

def chacha20_block(key, counter, nonce):
    state = list(struct.unpack('<4I', b'expand 32-byte k'))
    state += list(struct.unpack('<8I', key))
    state += [counter] + list(struct.unpack('<3I', nonce))
    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0,4,8,12); _quarter_round(working, 1,5,9,13)
        _quarter_round(working, 2,6,10,14); _quarter_round(working, 3,7,11,15)
        _quarter_round(working, 0,5,10,15); _quarter_round(working, 1,6,11,12)
        _quarter_round(working, 2,7,8,13); _quarter_round(working, 3,4,9,14)
    return struct.pack('<16I', *((w + s) & 0xFFFFFFFF for w, s in zip(working, state)))

def chacha20_encrypt(key, nonce, plaintext):
    out = bytearray()
    for i in range(0, len(plaintext), 64):
        block = chacha20_block(key, i // 64, nonce)
        chunk = plaintext[i:i+64]
        out.extend(a ^ b for a, b in zip(chunk, block))
    return bytes(out)

if __name__ == "__main__":
    key = bytes(range(32)); nonce = bytes(range(12))
    msg = b"Hello, ChaCha20! This is a test of the stream cipher."
    ct = chacha20_encrypt(key, nonce, msg)
    pt = chacha20_encrypt(key, nonce, ct)
    print(f"Original:  {msg}")
    print(f"Encrypted: {ct.hex()[:64]}...")
    print(f"Decrypted: {pt}")
    print(f"Match: {msg == pt}")
