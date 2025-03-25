import string

text = input("请输入文本：")
key = input("请输入密钥：")
type = input("选择加密还是解密（0加密，1解密）")
key = key.lower()


def crypt(text, key, type):
    ciphertext = ""
    l_key = len(key)
    index = 0

    for i in range(len(text)):
        if text[i] in string.ascii_lowercase:
            base_letter = 'a'
        elif text[i] in string.ascii_uppercase:
            base_letter = 'A'
        else:
            ciphertext += text[i]
            continue
        iv = ord(key[index % l_key]) - ord('a')
        offset = ord(text[i]) + iv if type == "0" else ord(text[i]) - iv
        ciphertext += chr((offset - ord(base_letter)) % 26 + ord(base_letter))
        index += 1
    return ciphertext


print(crypt(text, key, type))
