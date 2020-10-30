package core

import (
        //实现md5 hase算法的package，输入两个不同的值，一定返回指定长度的两个不同的值
	"crypto/md5"
        //只有一个new方法用来定义error值
	"errors"
        //net package用来实现网络操作
	"net"
        //实现排序算法，只要该类型实现Len(),Less(),Swap()
        //就可以使用sort包的方法进行排序
	"sort"
        //高级string操作，查找，拼接，分割string
	"strings"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)
//interface，stream(tcp)interface，packet(udp)interface
//stream and packet都是interface类型
type Cipher interface {
	StreamConnCipher
	PacketConnCipher
}

//tcp cipher，return一个net.Conn可以Reader and writer 或者获取端口IP
type StreamConnCipher interface {
	StreamConn(net.Conn) net.Conn
}
//udp cipher，return一个packetConn(UDP)
type PacketConnCipher interface {
	PacketConn(net.PacketConn) net.PacketConn
}

// ErrCipherNotSupported occurs when a cipher is not supported (likely because of security concerns)
//当不支持密码时报错，errors.New()函数定义的error
var ErrCipherNotSupported = errors.New("cipher not supported")
//定义const，都是string type，加密算法name
const (
	aeadAes128Gcm        = "AEAD_AES_128_GCM"
	aeadAes256Gcm        = "AEAD_AES_256_GCM"
	aeadChacha20Poly1305 = "AEAD_CHACHA20_POLY1305"
)

// List of AEAD ciphers: key size in bytes and constructor
//AEAD加密列表:函数构造和密钥大小一byte为单位
//一个字典，键为string，值为struct type
var aeadList = map[string]struct {
        //key(密钥)的size(大小)
	KeySize int
        //函数return一个cipher和一个error
	New     func([]byte) (shadowaead.Cipher, error)
}{
	aeadAes128Gcm:        {16, shadowaead.AESGCM},
	aeadAes256Gcm:        {32, shadowaead.AESGCM},
	aeadChacha20Poly1305: {32, shadowaead.Chacha20Poly1305},
}

// ListCipher returns a list of available cipher names sorted alphabetically.
//return从a~z排序的可用cipher
func ListCipher() []string {
	var l []string
	for k := range aeadList {
		l = append(l, k)
	}
        //sort.String按照字母顺序进行升序排序
	sort.Strings(l)
	return l
}

// PickCipher returns a Cipher of the given name. Derive key from password if given key is empty.
//return给定的cipher名称，如果key为空就从password派生key
func PickCipher(name string, key []byte, password string) (Cipher, error) {
       //将string转换为upper(大写)
	name = strings.ToUpper(name)
       
	switch name {
	case "DUMMY":
		return &dummy{}, nil
	case "CHACHA20-IETF-POLY1305":
		name = aeadChacha20Poly1305
	case "AES-128-GCM":
		name = aeadAes128Gcm
	case "AES-256-GCM":
		name = aeadAes256Gcm
	}
       
	if choice, ok := aeadList[name]; ok {
                //如果key为空就从password派生key
		if len(key) == 0 {
			key = kdf(password, choice.KeySize)
		}
                //key的大小发生错误
		if len(key) != choice.KeySize {
			return nil, shadowaead.KeySizeError(choice.KeySize)
		}
                //创建cipher
		aead, err := choice.New(key)
		return &aeadCipher{aead}, err
	}

	return nil, ErrCipherNotSupported
}
//aeadcipher 具体在shadowaead.Cipher下定义
type aeadCipher struct{ shadowaead.Cipher }
//TCP和UDP实现也在shadowaead下定义
func (aead *aeadCipher) StreamConn(c net.Conn) net.Conn { return shadowaead.NewConn(c, aead) }
func (aead *aeadCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return shadowaead.NewPacketConn(c, aead)
}

// dummy cipher does not encrypt
//虚拟密码不需要加密
type dummy struct{}
//直接return传入的网络实现本身
func (dummy) StreamConn(c net.Conn) net.Conn             { return c }
func (dummy) PacketConn(c net.PacketConn) net.PacketConn { return c }

// key-derivation function from original Shadowsocks
//从原来的shadowsocks派生函数
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
        //return一个使用md5校验的hash接口
	h := md5.New()
        //防止key的长度过小
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
                //获取hash
		b = h.Sum(b)
                //确保b的长度符合大小
		prev = b[len(b)-h.Size():]
                //REset会清空原先输入的数据
		h.Reset()
	}
	return b[:keyLen]
}
