package shadowaead

import (
        //实现了aes加密算法，NewCipher()return block interface
        //block中encrypt and decrypt 负责加密解密，将[]byte解密后输入任意类型中
	"crypto/aes"
        //实现了标准加密模块
	"crypto/cipher"
        //实现sha1加密算法的package
	"crypto/sha1"
        //只有一个New()方法来定义error
	"errors"
        //读写流控制
	"io"
        //实现各个数据类型之间的转换
	"strconv"
        //实现了ChaCha加密算法的package只有两个函数New() and Newx()
        //return都是cipher.AEDE() type
	"golang.org/x/crypto/chacha20poly1305"
        //有三个函数Expand(),Extrat(),New(),Expand and New 都会 return一个
        //io.Reader 类型的数据用来生成key而Extrat会直接return生成的key
	"golang.org/x/crypto/hkdf"
)

// ErrRepeatedSalt means detected a reused salt
//salt随机值，检测到重复的随机值
var ErrRepeatedSalt = errors.New("repeated salt detected")
//cipher interface
type Cipher interface {
        //key密钥大小
	KeySize() int
        //salt随机值大小
	SaltSize() int
        //encrypt加密 decrypt解密，输入一个salt随机值
        //return一个cipher.AEAD interface类型的数据包含
        //加密解密函数seal open
	Encrypter(salt []byte) (cipher.AEAD, error)
	Decrypter(salt []byte) (cipher.AEAD, error)
}
//定义error值
type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
        //hkdf.New()函数会返回一个io.Reader,sha1.New()会返回一个hase.Hase()
        //secret是密文，salt是随机值，info是随机值参考值
	r := hkdf.New(sha1.New, secret, salt, info)
        //io.Reader将r从中读取到的值写入outkey
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err) // should never happen
	}
}
//metaCipher(meta变化)
type metaCipher struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
}
//mateCipher实现KeySize() and SaltSize()方法
//两个方法都用来setting key的大小(key的大小必须大于16)
func (a *metaCipher) KeySize() int { return len(a.psk) }
func (a *metaCipher) SaltSize() int {
	if ks := a.KeySize(); ks > 16 {
		return ks
	}
	return 16
}
//metaCipher实现了Encrypter,Depcrypert加密解密算法，return cipher.AEDE类型的数据
func (a *metaCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	hkdfSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
	return a.makeAEAD(subkey)
}
func (a *metaCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	hkdfSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
	return a.makeAEAD(subkey)
}
//传入一个key，return一个由该密钥加密的cipher.AEDE()
func aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// AESGCM creates a new Cipher with a pre-shared key. len(psk) must be
// one of 16, 24, or 32 to select AES-128/196/256-GCM.
//创建一个有共享密钥控制的new password
func AESGCM(psk []byte) (Cipher, error) {
	switch l := len(psk); l {
	case 16, 24, 32: // AES 128/196/256
	default:
		return nil, aes.KeySizeError(l)
	}
	return &metaCipher{psk: psk, makeAEAD: aesGCM}, nil
}

// Chacha20Poly1305 creates a new Cipher with a pre-shared key. len(psk)
// must be 32.
//创建一个有共享密钥的new password
func Chacha20Poly1305(psk []byte) (Cipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, KeySizeError(chacha20poly1305.KeySize)
	}
	return &metaCipher{psk: psk, makeAEAD: chacha20poly1305.New}, nil
}
