import DPFace_Crypto_Base64
import DPFace_Crypto_RSA
import DPFace_Crypto_SHA256
import DPFace_Crypto_AES


if __name__ == "__main__":
    # 测试Base64
    _input0 = input("请输入要Base64加密的文本:")
    _input0_base = DPFace_Crypto_Base64.encode(_input0)
    print(_input0_base)
    _input_debase = DPFace_Crypto_Base64.decode(_input0_base)
    print(_input_debase)


    # 测试RSA
    (publickey, privatekey) = DPFace_Crypto_RSA.RSA_generateKeys()
    _input = input("请输入需要RSA加密的文本:")
    ciphertext = DPFace_Crypto_RSA.RSA_encrypt(_input, publickey)
    print("Base64+Rsa的密文为:", ciphertext)
    plaintext = DPFace_Crypto_RSA.RSA_decrypt(ciphertext, privatekey)
    print("解密得到的明文为:", plaintext)

    # 测试SHA256
    _input2 = input("请输入待Hash(SHA256)的文本:")
    print(DPFace_Crypto_SHA256.SHA256_hash(_input2))

    # 测试AES CBC
    (key, iv) = DPFace_Crypto_AES.AES_generateKeyIv()
    _input3 = input("请输入待AES加密的文本:")
    ciphertext = DPFace_Crypto_AES.AES_encrypt(_input3, key, iv)
    print("AES+base64密文:" + ciphertext)
    plaintext = DPFace_Crypto_AES.AES_decrypt(ciphertext, key, iv)
    print("原文:" + plaintext)
