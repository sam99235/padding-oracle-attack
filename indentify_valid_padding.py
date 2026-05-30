# ============================================================
# OBJECTIVE
# ============================================================
#
# Demonstrate that when the original plaintext ends with:
#
#     ... 03 03 03
#
# brute-forcing ONLY the last IV byte may produce
# MORE THAN ONE valid PKCS#7 padding.
#
# We then show how an additional modification
# (changing the second-last byte)
# distinguishes:
#
#     ...03 03 03  (original padding)
#
# from
#
#     ...03 03 01  (forced 01 padding)
#
# ============================================================


def valid_pkcs7(block):
    """
    Simulate the padding oracle.

    Returns True if PKCS#7 padding is valid.
    """

    pad = block[-1]

    # impossible padding length
    if pad < 1 or pad > len(block):
        return False

    return block[-pad:] == bytes([pad]) * pad


# ------------------------------------------------------------
# STEP 1
#
# Simulate an unknown intermediate state:
#
#     I = D(C1)
#
# In a real attack we do NOT know this value.
# We only use it here to simulate the server.
# ------------------------------------------------------------

I = bytes([
    0x10,
    0x20,
    0x30,
    0x40,
    0x50,
    0x60,
    0x70,
    0x80
])

# ------------------------------------------------------------
# STEP 2
#
# Choose IV so that:
#
#     P = I XOR IV
#
# ends with:
#
#     ...03 03 03
#
# ------------------------------------------------------------

IV = bytes([
    0x10,
    0x20,
    0x30,
    0x40,
    0x50,
    0x63,   # 0x60 XOR 0x63 = 0x03
    0x73,   # 0x70 XOR 0x73 = 0x03
    0x83    # 0x80 XOR 0x83 = 0x03
])

plaintext = bytes(i ^ v for i, v in zip(I, IV))

print("Original plaintext:")
print(plaintext.hex())
print("Last three bytes:", plaintext[-3:].hex())
print("Padding valid:", valid_pkcs7(plaintext))
print()

# ------------------------------------------------------------
# STEP 3
#
# Brute-force ONLY the last IV byte.
#
# This simulates the first stage of a padding oracle attack.
# ------------------------------------------------------------

valid_candidates = []

for guess in range(256):

    iv2 = bytearray(IV)
    iv2[-1] = guess

    p2 = bytes(i ^ v for i, v in zip(I, iv2))

    if valid_pkcs7(p2):
        valid_candidates.append((guess, p2))

print("VALID candidates found:")
print()

for guess, p2 in valid_candidates:
    print(
        f"IV[-1] = 0x{guess:02x} "
        f" --> plaintext tail = {p2[-3:].hex()}"
    )

print()
print("=" * 60)
print("VERIFICATION STEP")
print("=" * 60)

# ------------------------------------------------------------
# STEP 4
#
# For each VALID candidate:
#
# flip the second-last IV byte.
#
# If validity survives:
#
#     padding was interpreted as 01
#
# If validity breaks:
#
#     padding depended on multiple bytes
#     (e.g. original 03 03 03)
#
# ------------------------------------------------------------

for guess, _ in valid_candidates:

    iv2 = bytearray(IV)
    iv2[-1] = guess

    # Verification modification
    iv2[-2] ^= 1

    p3 = bytes(i ^ v for i, v in zip(I, iv2))

    print()
    print(f"Testing candidate IV[-1] = 0x{guess:02x}")
    print("Tail after verification:", p3[-3:].hex())

    if valid_pkcs7(p3):
        print("VALID survives")
        print("=> This was the forged 01-padding case.")
    else:
        print("VALID disappears")
        print("=> This depended on the original 03-padding.")