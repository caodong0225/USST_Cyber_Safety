import string

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

if __name__ == "__main__":
    text = "Nzal ck sg uhhey. A dbew sijdwl. Uhheyk sky yghx xgk imj aysdmb."
    key = "usst"
    # 0加密 1解密
    type = "1"
    key = key.lower()
    print(crypt(text, key, type))
