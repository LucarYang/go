package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

/*
常用加解密分为：
    对称式:     对称加密(也叫私钥加密)指加密和解密使用相同密钥的加密算法。具体算法主要有DES算法，3DES算法，TDEA算法，Blowfish算法，RC5算法，IDEA算法。
    非对称式:   指加密和解密使用不同密钥的加密算法，也称为公私钥加密。具体算法主要有RSA、Elgamal、背包算法、Rabin、D-H、ECC（椭圆曲线加密算法）。
    数字签名:   数字签名是非对称密钥加密技术与数字摘要技术的应用。主要算法有md5、hmac、sha1等。
*/

//MD5信息摘要算法是一种被广泛使用的密码散列函数，可以产生出一个128位（16进制，32个字符）的散列值（hash value），用于确保信息传输完整一致。
func GetMd5String(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

//HMAC是密钥相关的哈希运算消息认证码（Hash-based Message Authentication Code）的缩写，它通过一个标准算法，在计算哈希的过程中，把key混入计算过程中。
//key随意设置 data 要加密数据
func Hmac(key, data string) string {
    hash:= hmac.New(md5.New, []byte(key)) // 创建对应的md5哈希加密算法
    hash.Write([]byte(data))
    return hex.EncodeToString(hash.Sum([]byte("")))
}
func HmacSha256(key, data string) string {
    hash:= hmac.New(sha256.New, []byte(key)) //创建对应的sha256哈希加密算法
    hash.Write([]byte(data))
    return hex.EncodeToString(hash.Sum([]byte("")))
}

//SHA-1可以生成一个被称为消息摘要的160位（20字节）散列值，散列值通常的呈现形式为40个十六进制数.
func Sha1(data string) string {
    sha1 := sha1.New()
    sha1.Write([]byte(data))
    return hex.EncodeToString(sha1.Sum([]byte("")))
}

/*
AES 对称加密
	密码学中的高级加密标准（Advanced Encryption Standard，AES），又称Rijndael加密法，是美国联邦政府采用的一种区块加密标准。
	这个标准用来替代原先的DES（Data Encryption Standard），已经被多方分析且广为全世界所使用。
	AES中常见的有三种解决方案，分别为AES-128、AES-192和AES-256。
	如果采用真正的128位加密技术甚至256位加密技术，蛮力攻击要取得成功需要耗费相当长的时间。

	AES 有五种加密模式：

	电码本模式（Electronic Codebook Book (ECB)）、
	密码分组链接模式（Cipher Block Chaining (CBC)）、
	计算器模式（Counter (CTR)）、
	密码反馈模式（Cipher FeedBack (CFB)）
	输出反馈模式（Output FeedBack (OFB)）
*/

//ECB模式   出于安全考虑，golang默认并不支持ECB模式

func AESEncrypt(src []byte, key []byte) (encrypted []byte) {
    cipher, _ := aes.NewCipher(generateKey(key))
    length := (len(src) + aes.BlockSize) / aes.BlockSize
    plain := make([]byte, length*aes.BlockSize)
    copy(plain, src)
    pad := byte(len(plain) - len(src))
    for i := len(src); i < len(plain); i++ {
        plain[i] = pad
    }
    encrypted = make([]byte, len(plain))
    // 分组分块加密
    for bs, be := 0, cipher.BlockSize(); bs <= len(src); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
        cipher.Encrypt(encrypted[bs:be], plain[bs:be])
    }

    return encrypted
}

func AESDecrypt(encrypted []byte, key []byte) (decrypted []byte) {
    cipher, _ := aes.NewCipher(generateKey(key))
    decrypted = make([]byte, len(encrypted))
    //
    for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
        cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
    }

    trim := 0
    if len(decrypted) > 0 {
        trim = len(decrypted) - int(decrypted[len(decrypted)-1])
    }

    return decrypted[:trim]
}

func generateKey(key []byte) (genKey []byte) {
    genKey = make([]byte, 16)
    copy(genKey, key)
    for i := 16; i < len(key); {
        for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
            genKey[j] ^= key[i]
        }
    }
    return genKey
}

// CRT模式
//加密
func aesCtrCrypt(plainText []byte, key []byte) ([]byte, error) {

    //1. 创建cipher.Block接口
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    //2. 创建分组模式，在crypto/cipher包中
    iv := bytes.Repeat([]byte("1"), block.BlockSize())
    stream := cipher.NewCTR(block, iv)
    //3. 加密
    dst := make([]byte, len(plainText))
    stream.XORKeyStream(dst, plainText)

    return dst, nil
}

// CFB模式
func AesEncryptCFB(origData []byte, key []byte) (encrypted []byte) {
    block, err := aes.NewCipher(key)
    if err != nil {
        //panic(err)
    }
    encrypted = make([]byte, aes.BlockSize+len(origData))
    iv := encrypted[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        //panic(err)
    }
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(encrypted[aes.BlockSize:], origData)
    return encrypted
}
func AesDecryptCFB(encrypted []byte, key []byte) (decrypted []byte) {
    block, _ := aes.NewCipher(key)
    if len(encrypted) < aes.BlockSize {
        panic("ciphertext too short")
    }
    iv := encrypted[:aes.BlockSize]
    encrypted = encrypted[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(encrypted, encrypted)
    return encrypted
}

// OFB模式
func aesEncryptOFB( data[]byte,key []byte) ([]byte, error) {
    data = PKCS7Padding(data, aes.BlockSize)
    block, _ := aes.NewCipher([]byte(key))
    out := make([]byte, aes.BlockSize + len(data))
    iv := out[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewOFB(block, iv)
    stream.XORKeyStream(out[aes.BlockSize:], data)
    return out, nil
}

func aesDecryptOFB( data[]byte,key []byte) ([]byte, error) {
    block, _ := aes.NewCipher([]byte(key))
    iv  := data[:aes.BlockSize]
    data = data[aes.BlockSize:]
    if len(data) % aes.BlockSize != 0 {
        return nil, fmt.Errorf("data is not a multiple of the block size")
    }

    out := make([]byte, len(data))
    mode := cipher.NewOFB(block, iv)
    mode.XORKeyStream(out, data)

    out= PKCS7UnPadding(out)
    return out, nil
}
//补码
//AES加密数据块分组长度必须为128bit(byte[16])，密钥长度可以是128bit(byte[16])、192bit(byte[24])、256bit(byte[32])中的任意一个。
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
    padding := blocksize - len(ciphertext)%blocksize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}
//去码
func PKCS7UnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}

//RSA加密  --首先使用openssl生成公私钥

// 私钥生成
//openssl genrsa -out rsa_private_key.pem 1024
var privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDcGsUIIAINHfRTdMmgGwLrjzfMNSrtgIf4EGsNaYwmC1GjF/bM
h0Mcm10oLhNrKNYCTTQVGGIxuc5heKd1gOzb7bdTnCDPPZ7oV7p1B9Pud+6zPaco
qDz2M24vHFWYY2FbIIJh8fHhKcfXNXOLovdVBE7Zy682X1+R1lRK8D+vmQIDAQAB
AoGAeWAZvz1HZExca5k/hpbeqV+0+VtobMgwMs96+U53BpO/VRzl8Cu3CpNyb7HY
64L9YQ+J5QgpPhqkgIO0dMu/0RIXsmhvr2gcxmKObcqT3JQ6S4rjHTln49I2sYTz
7JEH4TcplKjSjHyq5MhHfA+CV2/AB2BO6G8limu7SheXuvECQQDwOpZrZDeTOOBk
z1vercawd+J9ll/FZYttnrWYTI1sSF1sNfZ7dUXPyYPQFZ0LQ1bhZGmWBZ6a6wd9
R+PKlmJvAkEA6o32c/WEXxW2zeh18sOO4wqUiBYq3L3hFObhcsUAY8jfykQefW8q
yPuuL02jLIajFWd0itjvIrzWnVmoUuXydwJAXGLrvllIVkIlah+lATprkypH3Gyc
YFnxCTNkOzIVoXMjGp6WMFylgIfLPZdSUiaPnxby1FNM7987fh7Lp/m12QJAK9iL
2JNtwkSR3p305oOuAz0oFORn8MnB+KFMRaMT9pNHWk0vke0lB1sc7ZTKyvkEJW0o
eQgic9DvIYzwDUcU8wJAIkKROzuzLi9AvLnLUrSdI6998lmeYO9x7pwZPukz3era
zncjRK3pbVkv0KrKfczuJiRlZ7dUzVO0b6QJr8TRAA==
-----END RSA PRIVATE KEY-----
`)
// 公钥: 根据私钥生成
//openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcGsUIIAINHfRTdMmgGwLrjzfM
NSrtgIf4EGsNaYwmC1GjF/bMh0Mcm10oLhNrKNYCTTQVGGIxuc5heKd1gOzb7bdT
nCDPPZ7oV7p1B9Pud+6zPacoqDz2M24vHFWYY2FbIIJh8fHhKcfXNXOLovdVBE7Z
y682X1+R1lRK8D+vmQIDAQAB
-----END PUBLIC KEY-----
`)

// 加密
func RsaEncrypt(origData []byte) ([]byte, error) {
    //解密pem格式的公钥
    block, _ := pem.Decode(publicKey)
    if block == nil {
        return nil, errors.New("public key error")
    }
    // 解析公钥
    pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    // 类型断言
    pub := pubInterface.(*rsa.PublicKey)
    //加密
    return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// 解密
func RsaDecrypt(ciphertext []byte) ([]byte, error) {
    //解密
    block, _ := pem.Decode(privateKey)
    if block == nil {
        return nil, errors.New("private key error!")
    }
    //解析PKCS1格式的私钥
    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    // 解密
    return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}


func main() {

	fmt.Println("md5加密："+GetMd5String("1234"))
	fmt.Println("md5哈希加密算法:"+Hmac("123","123"))
	fmt.Println("SHA-1加密算法:"+Sha1("123"))
	fmt.Println("AES-ECB模式------------------------------------")
	source:="hello world"
    fmt.Println("原字符：",source)
	//16byte密钥
    key:="1443flfsaWfdas"
    encryptCode:=AESEncrypt([]byte(source),[]byte(key))
    fmt.Println("密文：",encryptCode)

    decryptCode:=AESDecrypt(encryptCode,[]byte(key))

    fmt.Println("解密：",string(decryptCode))

	fmt.Println("AES-CRT模式------------------------------------")
	source="hello world"
    fmt.Println("原字符：",source)

    key="1443flfsaWfdasds"
    encryptCRTCode,_:=aesCtrCrypt([]byte(source),[]byte(key))
    fmt.Println("密文：",encryptCRTCode)

    decryptCRTCode,_:=aesCtrCrypt(encryptCRTCode,[]byte(key))

    fmt.Println("解密：",string(decryptCRTCode))

	fmt.Println("AES-CFB模式------------------------------------")
	source="hello world"
    fmt.Println("原字符：",source)
    key="ABCDEFGHIJKLMNO1"//16位
    encryptCFBCode:=AesEncryptCFB([]byte(source),[]byte(key))
    fmt.Println("密文：",hex.EncodeToString(encryptCFBCode))
    decryptCFBCode:=AesDecryptCFB(encryptCFBCode,[]byte(key))

    fmt.Println("解密：",string(decryptCFBCode))

	fmt.Println("AES-CFB模式------------------------------------")
	source="hello world"
    fmt.Println("原字符：",source)
    key="1111111111111111"//16位  32位均可
    encryptOFBCode,_:=aesEncryptOFB([]byte(source),[]byte(key))
    fmt.Println("密文：",hex.EncodeToString(encryptOFBCode))
    decryptOFBCode,_:=aesDecryptOFB(encryptOFBCode,[]byte(key))


    fmt.Println("解密：",string(decryptOFBCode))

	fmt.Println("RAS加密------------------------------------")
	data, _ := RsaEncrypt([]byte("hello world"))
    fmt.Println(base64.StdEncoding.EncodeToString(data))
    origData, _ := RsaDecrypt(data)
    fmt.Println(string(origData))

}