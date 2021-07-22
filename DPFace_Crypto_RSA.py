# DPFace_Crypto_RSA
import base64
import rsa
import DPFace_Crypto_Base64


# 可加密的字符串长度，默认为512
len_rsa = 512


# RSA.generateKeys() -> (Base64公钥, Base64私钥)
def RSA_generateKeys() -> (str, str):
    # 生成公钥、私钥
    (pubkey, privkey) = rsa.newkeys(len_rsa)
    # Base64处理并返回
    return (DPFace_Crypto_Base64.encode(str(pubkey)), DPFace_Crypto_Base64.encode(str(privkey)))


# RSA.encrypt(明文, Base64公钥) -> Base64密文
def RSA_encrypt(plaintext: str, publicKey: str):
    # Base64公钥 -> 公钥
    publickey = DPFace_Crypto_Base64.decode(publicKey)
    n_beg = 10
    n_end = publickey.find(",", n_beg, len(publickey))
    e_beg = publickey.find(" ", n_end, len(publickey)) + 1
    e_end = len(publickey)-1
    n = int(publickey[n_beg:n_end])
    e = int(publickey[e_beg:e_end])
    # 明文编码格式
    content = plaintext.encode("utf-8")
    # 明文 -> HEX bytes
    ciphertext = rsa.encrypt(content, rsa.PublicKey(n, e))
    # ciphertext = rsa.encrypt(content, pubkey_tmp)
    # HEX bytes -> HEX str
    return DPFace_Crypto_Base64.encode(str(base64.b16encode(ciphertext)))


# RSA.decrypt(Base64密文, Base64私钥) -> 明文
def RSA_decrypt(ciphertext_base: str, privateKey: str):
    # Base64密文 -> 密文(HEX str)
    tmp = DPFace_Crypto_Base64.decode(ciphertext_base)
    ciphertext_hex = tmp[2:len(tmp)-1]
    # HEX str -> HEX bytes
    ciphertext = base64.b16decode(ciphertext_hex)
    # Base64私钥 -> str私钥
    privatekey_str = DPFace_Crypto_Base64.decode(privateKey)
    # str私钥 -> 私钥
    n_beg = 11
    n_end = privatekey_str.find(",", n_beg, len(privatekey_str))
    e_beg = privatekey_str.find(" ", n_end, len(privatekey_str)) + 1
    e_end = privatekey_str.find(",", e_beg, len(privatekey_str))
    d_beg = privatekey_str.find(" ", e_end, len(privatekey_str)) + 1
    d_end = privatekey_str.find(",", d_beg, len(privatekey_str))
    p_beg = privatekey_str.find(" ", d_end, len(privatekey_str)) + 1
    p_end = privatekey_str.find(",", p_beg, len(privatekey_str))
    q_beg = privatekey_str.find(" ", p_end, len(privatekey_str)) + 1
    q_end = len(privatekey_str) - 1
    n = int(privatekey_str[n_beg:n_end])
    e = int(privatekey_str[e_beg:e_end])
    d = int(privatekey_str[d_beg:d_end])
    p = int(privatekey_str[p_beg:p_end])
    q = int(privatekey_str[q_beg:q_end])
    privatekey = rsa.PrivateKey(n, e, d, p, q)
    # 私钥解密
    content = rsa.decrypt(ciphertext, privatekey)
    # 明文编码格式
    content = content.decode("utf-8")
    return content
