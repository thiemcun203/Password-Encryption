import base64
import os

def blowfish_f_function(half_block, s):
    # The real implementation involves complex operations with the S-boxes
    return half_block

def encrypt_block(p, s, block):
    # Blowfish operates on two 32-bit halves of the 64-bit block
    left = int.from_bytes(block[:4], byteorder='big')
    right = int.from_bytes(block[4:], byteorder='big')

    # 16 rounds of the Feistel network
    for i in range(16):
        left ^= p[i]
        right ^= blowfish_f_function(left, s)

        # Swap left and right for the next round
        left, right = right, left

    # Undo the last swap
    left, right = right, left

    # Final round: XOR with the last two P-array values
    right ^= p[16]
    left ^= p[17]

    # Combine the halves and return the encrypted block
    encrypted_block = left.to_bytes(4, byteorder='big') + right.to_bytes(4, byteorder='big')
    return encrypted_block


def feistel_round(left_half, right_half, round_key, s_boxes):
    left_int = int.from_bytes(left_half, byteorder='big')
    right_int = int.from_bytes(right_half, byteorder='big')

    processed_right = blowfish_f_function(right_int, s_boxes)
    processed_right ^= round_key

    new_left_int = left_int ^ processed_right
    new_left_half = new_left_int.to_bytes(4, byteorder='big')

    new_right_half = left_half
    return new_right_half, new_left_half

def encrypt_ecb(p, s, ctext):
    if len(ctext) % 8 != 0:
        raise ValueError("Ciphertext must be a multiple of 8 bytes (64 bits) for Blowfish")
    encrypted_text = b''
    for i in range(0, len(ctext), 8):
        block = ctext[i:i+8]
        left_half = block[:4]
        right_half = block[4:]

        for round in range(16):
            left_half, right_half = feistel_round(left_half, right_half, p[round], s)

        encrypted_block = right_half + left_half  # Swap the halves
        encrypted_text += encrypted_block

    return encrypted_text


def eks_blowfish_setup(password, salt, cost):
    # Initialize P and S with pi digits - real implementation needed
    p = [0] * 18
    s = [[0] * 256 for _ in range(4)]

    # Expand key - real implementation needed
    p, s = expand_key(p, s, password, salt)

    # Expensive key setup
    for _ in range(2 ** cost):
        p, s = expand_key(p, s, password, b'')
        p, s = expand_key(p, s, salt,  b'')

    return p, s

def expand_key(p, s, password, salt):
    # Mix the password into the P-array
    password_len = len(password)
    for i in range(len(p)):
        p[i] ^= int.from_bytes(password[(i * 4) % password_len: (i * 4) % password_len + 4], 'big')

    # Initialize an 8-byte (64-bit) block as bytearray
    block = bytearray(8)  # Using bytearray

    # Process the P-array and S-boxes
    for i in range(0, len(p), 2):
        # Mixing in the salt
        for j in range(4):
            if len(salt) > 0:
                block[j] ^= salt[j % len(salt)]
                block[j + 4] ^= salt[(j + 4) % len(salt)]

        # Encrypt the block with the current state
        encrypted_block = encrypt_block(p, s, bytes(block))  # Convert block to bytes for encryption

        # Update the P-array with the encrypted block
        p[i] = int.from_bytes(encrypted_block[0:4], 'big')
        p[i + 1] = int.from_bytes(encrypted_block[4:8], 'big')

    # Process each S-box similarly
    for i in range(4):
        for j in range(0, 256, 2):
            encrypted_block = encrypt_block(p, s, bytes(block))  # Convert block to bytes for encryption
            s[i][j] = int.from_bytes(encrypted_block[0:4], 'big')
            s[i][j + 1] = int.from_bytes(encrypted_block[4:8], 'big')

    return p, s


def bcrypt(cost, salt, password):
    # Prepare the initial Blowfish state
    p, s = eks_blowfish_setup(password, salt, cost)

    # Encrypt the text 64 times
    ctext = password
    for _ in range(64):
        ctext = encrypt_ecb(p, s, ctext)

    # Base64 encode the salt and the ciphertext
    encoded_salt = base64.b64encode(salt).decode('utf-8')
    encoded_ctext = base64.b64encode(ctext).decode('utf-8')

    # Truncate the encoded strings to the desired length (22 characters for salt, 31 for hash)
    encoded_salt = encoded_salt[:22]
    encoded_ctext = encoded_ctext[:31]

    # Return the formatted bcrypt hash string
    bcrypt_version = '2a'  # Placeholder for bcrypt version
    return f"${bcrypt_version}${cost}${encoded_salt}{encoded_ctext}"

# Example usage
cost_factor = 6
salt = os.urandom(16)  # Secure random salt
print("Salt:", salt)

password = b"example_password"
# Hashing the password

bcrypt_hash = bcrypt(cost_factor, salt, password)
print("Bcrypt Hash:", bcrypt_hash)

