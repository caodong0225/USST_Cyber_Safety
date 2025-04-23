from crypto import AES, string_to_hex, hex_to_string

aes = AES()
key = 'test'
RoundKeys = aes.round_key_generator(string_to_hex(key))

# 加密
plaintext = 'plaintext'
# 0x00112233445566778899aabbccddeeff -> b'\x11"3DUfw\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
plaintext = aes.num_2_16bytes(string_to_hex(plaintext))
ciphertext = aes.aes_encrypt(plaintext, RoundKeys)
print('ciphertext = ' + hex(aes._16bytes2num(ciphertext)))

# 解密
ciphertext = 0xe006bc8a15ef40145bc7024e2d2db8e8
ciphertext = aes.num_2_16bytes(ciphertext)
plaintext = aes.aes_decrypt(ciphertext, RoundKeys)
print('plaintext = ' + hex_to_string(aes._16bytes2num(plaintext)))