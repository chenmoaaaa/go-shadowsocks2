package shadowaead

import (
        //string可以表示为[]byte，因此bytes包下的函数同strings包一样
	"bytes"
        //实现了标准加密解密的包
	"crypto/cipher"
        //用于加密解密更安全的随机数生成器
	"crypto/rand"
        //io package用于Reader Writer
	"io"
        //用于网络操作
	"net"

	"github.com/shadowsocks/go-shadowsocks2/internal"
)

// payloadSizeMask is the maximum size of payload in bytes.
//有效载荷大小是有效载荷大小的最大值
const payloadSizeMask = 0x3FFF // 16*1024 - 1
//io.Writer cipher.AEAD是interface
//nonce buf是byte[]类型可以视做string
type writer struct {
	io.Writer
	cipher.AEAD
	nonce []byte
	buf   []byte
}

// NewWriter wraps an io.Writer with AEAD encryption.
//包装一个新的Writer与AEAD
//参数为 io.Writer cipher.AEAD return一个io.Writer
func NewWriter(w io.Writer, aead cipher.AEAD) io.Writer { return newWriter(w, aead) }
//return一个指针类型
func newWriter(w io.Writer, aead cipher.AEAD) *writer {
	return &writer{
		Writer: w,
		AEAD:   aead,
		buf:    make([]byte, 2+aead.Overhead()+payloadSizeMask+aead.Overhead()),
		nonce:  make([]byte, aead.NonceSize()),
	}
}

// Write encrypts b and writes to the embedded io.Writer.
//写入加密与写入到嵌入的io.Writer
func (w *writer) Write(b []byte) (int, error) {
        //NewBuffer()将[]byte包装成bytes package下的
        //Buffer对象实现了io包下的Reader Writer interface
        //ReaderFrom()从bytes.NewBuffer()中读取数据，再由Writer写入，n是写入的字节数
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

// ReadFrom reads from the given io.Reader until EOF or error, encrypts and
// writes to the embedded io.Writer. Returns number of bytes read from r and
// any error encountered.
//ReadFrom读取给定的io。读取器直到EOF或错误，
//加密并写入嵌入的io.Writer。返回从r读取的字节数和遇到的任何错误。
func (w *writer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		buf := w.buf
		payloadBuf := buf[2+w.Overhead() : 2+w.Overhead()+payloadSizeMask]
                //从r中读取数据在写入payloadBuf，return读取到的字节数和错误
		nr, er := r.Read(payloadBuf)
                //如果读取到的字节数大于0，说明读取成功
		if nr > 0 {
                        //n=nr+n
			n += int64(nr)
                        //从buf中提取指定长度的数据
			buf = buf[:2+w.Overhead()+nr+w.Overhead()]
                        //从payloadBuf中提取出有效的字节数
			payloadBuf = payloadBuf[:nr]
                        //buf[0]==byte(nr位运算右移8位)，byte==byte(nr)
			buf[0], buf[1] = byte(nr>>8), byte(nr) // big-endian payload size//大端模式的有效载荷
                        //将数据填入buf中
			w.Seal(buf[:0], w.nonce, buf[:2], nil)
			increment(w.nonce)
                        //将数据填入payloadBuf中
			w.Seal(payloadBuf[:0], w.nonce, payloadBuf, nil)
			increment(w.nonce)
                        //将buf中的数据写入w中
			_, ew := w.Writer.Write(buf)
			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			break
		}
	}

	return n, err
}
//reader类型包括io.Reader cipher.AEAD interface
type reader struct {
	io.Reader
	cipher.AEAD
        //只用一次的随机值
	nonce    []byte
        //缓冲区
	buf      []byte
        //leftover剩余的
	leftover []byte
}

// NewReader wraps an io.Reader with AEAD decryption.
//NewReader包装 io.Reader 包括Reader和AEDA decrypt
//参数为io.Reader cipher.AEAD类型的数据，返回的是一个指针类型的type read struct
func NewReader(r io.Reader, aead cipher.AEAD) io.Reader { return newReader(r, aead) }
//参数为io.Reader cipher.AEAD类型的interface接口，返回一个指针类型的type Read struct
func newReader(r io.Reader, aead cipher.AEAD) *reader {
	return &reader{
		Reader: r,
		AEAD:   aead,
                //buf的大小为额外开销加上工作沉余空间
		buf:    make([]byte, payloadSizeMask+aead.Overhead()),
                //nonce的大小
		nonce:  make([]byte, aead.NonceSize()),
	}
}

// read and decrypt a record into the internal buffer. Return decrypted payload length and any error encountered
//将内容解密并读取缓冲区中，并return读取到的字节长度和遇到的错误.
func (r *reader) read() (int, error) {
	// decrypt payload size
        //解密的有效载荷大小
        //确保buf有足够的空间接受数据
	buf := r.buf[:2+r.Overhead()]
        //将从r中读取内容填入buf中
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}
        //将内容解密并填入buf中
	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}
        //设置大小
        //<<，＆都是位运算符，<<8就是乘以2的8次方，＆是按按位与运算
        //2位皆为1时，才为1，只要有1位不为1，那就是为0
	size := (int(buf[0])<<8 + int(buf[1])) & payloadSizeMask

	// decrypt payload
        //解密有效载荷从

        //确保buf有足够的空间接受数据
	buf = r.buf[:size+r.Overhead()]
        //io.ReadFull(r.Reader, buf)将从io.Reader中读取的数据，存入buf中
	_, err = io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}
        //将解析后的数据存入buf[:0]中
	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to b.
//从嵌入式io读取，解密并写入b在
//接受者是指针类型，参数为[]byte，返回值是int
func (r *reader) Read(b []byte) (int, error) {
	// copy decrypted bytes (if any) from previous record first
        //从以前的记录在哪里复制解密的字节(如果有的话)
	if len(r.leftover) > 0 {
               //copy()将r.leftover写入b中
		n := copy(b, r.leftover)
                //去除此处读取的数据
		r.leftover = r.leftover[n:]
		return n, nil
	}
        //得到能够有效读取的字节数n
	n, err := r.read()
        //复制r.buf中的数据到b中
	m := copy(b, r.buf[:n])
	if m < n { // insufficient len(b), keep leftover for next read//当b的长度不够是留下一部分
		r.leftover = r.buf[m:n]
	}
	return m, err
}

// WriteTo reads from the embedded io.Reader, decrypts and writes to w until
// there's no more data to write or when an error occurs. Return number of
// bytes written to w and any error encountered.
//读写从嵌入式io，返回成功读写的次数
func (r *reader) WriteTo(w io.Writer) (n int64, err error) {
	// write decrypted bytes left over from previous record
        //写入从前一个记录留下来的解密字节的
	for len(r.leftover) > 0 {
		nw, ew := w.Write(r.leftover)
                //去除此处读取到的数据
		r.leftover = r.leftover[nw:]
		n += int64(nw)
		if ew != nil {
			return n, ew
		}
	}

	for {
               //返回正确读取到的字数
		nr, er := r.read()
		if nr > 0 {
                        //将r.buf中的写入
			nw, ew := w.Write(r.buf[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract (using src.WriteTo shortcut)
				err = er
			}
			break
		}
	
}

	return n, err
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
//增量小端编码的无符号整数b.溢出时绕圈。
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
//tcp网络结构
type streamConn struct {
	net.Conn
	Cipher
	r *reader
	w *writer
}
//接受者指针类型的type streamConn struct,无参数，只返回error
func (c *streamConn) initReader() error {
       //定义随机值的大小
	salt := make([]byte, c.SaltSize())
        //将从网络中读取的数据存入随机值中
        //io.ReadFull从c.Conn.中读取数据填入salt
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
        //测试随机值
	if internal.TestSalt(salt) {
		return ErrRepeatedSalt
	}
       //获取加密方式
	aead, err := c.Decrypter(salt)
	if err != nil {
		return err
	}
        //增加随机值
	internal.AddSalt(salt)
        //获取一个指针类型的本文件中reader数据，包括io.Reader cipher.AEAD interface, buf leftover byte[]
	c.r = newReader(c.Conn, aead)
	return nil
}
//接受者是一个type streamConn struct，参数b []byte,返回值int
func (c *streamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
        //将数据读取存入b中并返回成功读取到的字节数
	return c.r.Read(b)
}
//接受者是一个type streamConn struct,参数是io.Writer,返回值是int64
func (c *streamConn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
        //将数据写入参数w io.Writer中
	return c.r.WriteTo(w)
}
//接受者是一个type streamConn struct，无参数，返回值只有一个error
func (c *streamConn) initWriter() error {
        //定义salt的大小
	salt := make([]byte, c.SaltSize())
        //将随机生成的数据存入salt中
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
        //获取cipher.AEAD
	aead, err := c.Encrypter(salt)
	if err != nil {
		return err
	}
        //将数据写入数据流中
	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}
	internal.AddSalt(salt)
        //或取一个本文件中的writer类型的数据
	c.w = newWriter(c.Conn, aead)
	return nil
}
//将数据写入streamConn w中的数据流中
func (c *streamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}
//将读取到的数据写入w中
func (c *streamConn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

// NewConn wraps a stream-oriented net.Conn with cipher.
//return返回一个本文件定义的streamConn，其实现了net.Conn
func NewConn(c net.Conn, ciph Cipher) net.Conn { return &streamConn{Conn: c, Cipher: ciph} }
