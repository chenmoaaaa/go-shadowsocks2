package main

import (
	//带有buf的高效io
	"bufio"
        //只有一个New函数，用来定制error
	"errors"
        //用来实现文件的读写操作
	"io"
        //提供一些io操作函数，如一次性读取全部文件，读取文件名，创建临时文件等
	"io/ioutil"
        //网络操作包
	"net"
        //解析用户系统相关的包
	"os"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Create a SOCKS server listening on addr and proxy to server.
//创建一个服务器listening address和 proxy to server
func socksLocal(addr, server string, shadow func(net.Conn) net.Conn) {
	logf("SOCKS proxy %s <-> %s", addr, server)
	tcpLocal(addr, server, shadow, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// Create a TCP tunnel from addr to target via server.
创建一个tcp tunnel通过address 到达 target
func tcpTun(addr, server, target string, shadow func(net.Conn) net.Conn) {
        //解析目标地址
	tgt := socks.ParseAddr(target)
	if tgt == nil {
		logf("invalid target address %q", target)
		return
	}
	logf("TCP tunnel %s <-> %s <-> %s", addr, server, target)
	tcpLocal(addr, server, shadow, func(net.Conn) (socks.Addr, error) { return tgt, nil })
}

// Listen on addr and proxy to server to reach target from getAddr.
//监听目标地址和代理服务器，从getaddr到达目标
func tcpLocal(addr, server string, shadow func(net.Conn) net.Conn, getAddr func(net.Conn) (socks.Addr, error)) {
        //监听地址
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	for {
                //等待并返回接受到的链接
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %s", err)
			continue
		}

		go func() {
                        //确保能够关闭stream
			defer c.Close()
			tgt, err := getAddr(c)
			if err != nil {

				// UDP: keep the connection until disconnect then free the UDP socket
                                //保持连接直到连接断开释放udp套接字
				if err == socks.InfoUDPAssociate {
                                        //创建一个缓冲区
					buf := make([]byte, 1)
					// block here
					for {
                                                //从数据流中读取数据填入buf
						_, err := c.Read(buf)
                                                //如果读取错误则重新读取
						if err, ok := err.(net.Error); ok && err.Timeout() {
							continue
						}
						logf("UDP Associate End.")
                                                //读取成功则结束这个for%
						return
					}
				}

				logf("failed to get target address: %v", err)
				return
			}
                        //发起链接
			rc, err := net.Dial("tcp", server)
			if err != nil {
				logf("failed to connect to server %v: %v", server, err)
				return
			}
                        //确保能够关闭链接
			defer rc.Close()
                        //判断是否启用tcpcork
			if config.TCPCork {
				rc = timedCork(rc, 10*time.Millisecond, 1280)
			}
			rc = shadow(rc)
                        //将读取的数据写入rc中
			if _, err = rc.Write(tgt); err != nil {
				logf("failed to send target address: %v", err)
				return
			}

			logf("proxy %s <-> %s <-> %s", c.RemoteAddr(), server, tgt)
			if err = relay(rc, c); err != nil {
				logf("relay error: %v", err)
			}
		}()
	}
}

// Listen on addr for incoming connections.
func tcpRemote(addr string, shadow func(net.Conn) net.Conn) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	logf("listening TCP on %s", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer c.Close()
			if config.TCPCork {
				c = timedCork(c, 10*time.Millisecond, 1280)
			}
			sc := shadow(c)

			tgt, err := socks.ReadAddr(sc)
			if err != nil {
				logf("failed to get target address from %v: %v", c.RemoteAddr(), err)
				// drain c to avoid leaking server behavioral features
				// see https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/
				_, err = io.Copy(ioutil.Discard, c)
				if err != nil {
					logf("discard error: %v", err)
				}
				return
			}

			rc, err := net.Dial("tcp", tgt.String())
			if err != nil {
				logf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()

			logf("proxy %s <-> %s", c.RemoteAddr(), tgt)
			if err = relay(sc, rc); err != nil {
				logf("relay error: %v", err)
			}
		}()
	}
}

// relay copies between left and right bidirectionally
//在左和右之间双向终中继副本
func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}

type corkedConn struct {
	net.Conn
	bufw   *bufio.Writer
	corked bool
	delay  time.Duration
	err    error
	lock   sync.Mutex
	once   sync.Once
}

func timedCork(c net.Conn, d time.Duration, bufSize int) net.Conn {
	return &corkedConn{
		Conn:   c,
		bufw:   bufio.NewWriterSize(c, bufSize),
		corked: true,
		delay:  d,
	}
}

func (w *corkedConn) Write(p []byte) (int, error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.corked {
		w.once.Do(func() {
			time.AfterFunc(w.delay, func() {
				w.lock.Lock()
				defer w.lock.Unlock()
				w.corked = false
				w.err = w.bufw.Flush()
			})
		})
		return w.bufw.Write(p)
	}
	return w.Conn.Write(p)
}
