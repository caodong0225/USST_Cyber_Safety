from crypto import AES, string_to_hex, hex_to_string

aes = AES()
key = 'test'
RoundKeys = aes.round_key_generator(string_to_hex(key))

# 加密
plaintext = 'testtest'
plaintext = aes.num_2_16bytes(string_to_hex(plaintext))
ciphertext = aes.aes_encrypt(plaintext, RoundKeys)
print('ciphertext = ' + hex(aes._16bytes2num(ciphertext)))

# 解密
ciphertext = 0x766f8156096dea2340434c3344646819
ciphertext = aes.num_2_16bytes(ciphertext)
plaintext = aes.aes_decrypt(ciphertext, RoundKeys)
print('plaintext = ' + hex_to_string(aes._16bytes2num(plaintext)))