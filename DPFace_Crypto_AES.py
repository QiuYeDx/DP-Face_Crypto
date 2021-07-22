import base64
from Cryptodome.Cipher import AES
from Cryptodome import Random
# 数据块的大小  16位
BS = 16
# CBC模式 相对安全 因为有偏移向量 iv 也是16位字节的
mode = AES.MODE_CBC
# 填充函数 因为AES加密是一段一段加密的  每段都是BS位字节，不够的话是需要自己填充的
pad = lambda s: s + (BS - len(s.encode()) % BS) * chr(BS - len(s.encode()) % BS)
# 将填充的数据剔除
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


# AES_generateKeyIv() -> (公钥, 偏移)
def AES_generateKeyIv() -> (str, int):
    # CBC加密需要一个十六位的key(密钥)和一个十六位iv(偏移量)
    key = 'neudpfacetuandui'
    # 随机获取iv
    iv = Random.new().read(AES.block_size)
    return (key, iv)


def AES_encrypt(plaintext: str, key: str, iv: int) -> str:
    # 输入合法化
    plaintext = pad(plaintext).encode()
    # 定义初始化
    cipher = AES.new(base64.b16encode(key), mode, base64.b16encode(iv))
    # 加密并返回
    return base64.b64encode(cipher.encrypt(plaintext)).decode()


def AES_decrypt(ciphertext: str, key: str, iv: int):
    # 将密文进行base64解码
    ciphertext = base64.b64decode(ciphertext)
    # 初始化自定义
    cipher = AES.new(base64.b16encode(key), mode, base64.b16encode(iv))
    # 返回utf-8格式的数据
    return unpad(cipher.decrypt(ciphertext[:])).decode()
