package main

import (
        //crypto/rand是用于加解密的随机数生成器
	"crypto/rand"
        //base64方法编码或是解码
	"encoding/base64"
        //flag包设置，接受，处理命令行参数
	"flag"
         //fmt输出
	"fmt"
        //实现io流的读写功能
	"io"
        //日志
	"log"
        //用于解析，提取URL类型的数据
	"net/url"
        //进行系统的基本操作，如文件、目录、执行命令
	"os"
        //监听系统的信号
	"os/signal"
        //高级字符串操作，如查找、拼接、分割、读写
	"strings"
        //系统调用包
	"syscall"
        //时间处理包
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var config struct {
        //是否启用verbose
	Verbose bool
        //UDP超时时间 time包下的数据结构用来表示持续时间
	UDPTimeout time.Duration
        //是否启用tcpcork模式
	TCPCork    bool
}

func main() {
	var flags struct {
		Client     string
		Server     string
                //cipher是指一套包含加密解密的密码系统
		Cipher     string
		Key        string
                //password是指一个口令
		Password   string
                //注册机
		Keygen     int
		Socks      string
                //redir重定向
		RedirTCP   string
		RedirTCP6  string
                //通道
		TCPTun     string
		UDPTun     string
                //释放启用协议
		UDPSocks   bool
		UDP        bool
		TCP        bool
                //plugin插件
		Plugin     string
		PluginOpts string
	}
        //flag定义参数时会返回一个指针类型的变量，而var方法会把变量绑定的指定地址值也就是变量
        //第一个参数为需要绑定的地址值，第二个是参数名称，第三个是默认值，第四个是提示
	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
        //选择加密方式
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
        //选择base64方法的密钥，没有默认值如果为空则从密码派生
	flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
        //生成给定长度的base64位编码密钥
	flag.IntVar(&flags.Keygen, "keygen", 0, "generate a base64url-encoded random key of given length in byte")
	flag.StringVar(&flags.Password, "password", "", "password")
        //服务器的监听地址
	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
        //客户端的链接地址
	flag.StringVar(&flags.Client, "c", "", "client connect address or url")
        //只适用于客户端socks server的listen地址
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
        //是否为socks启用UDP
	flag.BoolVar(&flags.UDPSocks, "u", false, "(client-only) Enable UDP support for SOCKS")
        //从指定地址 redirect tcp
	flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
        //tcp，udp通道
	flag.StringVar(&flags.TCPTun, "tcptun", "", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
        //差件and插件选项
	flag.StringVar(&flags.Plugin, "plugin", "", "Enable SIP003 plugin. (e.g., v2ray-plugin)")
	flag.StringVar(&flags.PluginOpts, "plugin-opts", "", "Set SIP003 plugin options. (e.g., \"server;tls;host=mydomain.me\")")
        //只适用于server是否启用tcp or udp支持 udp默认值为false
	flag.BoolVar(&flags.UDP, "udp", false, "(server-only) enable UDP support")
	flag.BoolVar(&flags.TCP, "tcp", true, "(server-only) enable TCP support")
        //设置tcpcock
	flag.BoolVar(&config.TCPCork, "tcpcork", false, "coalesce writing first few packets")
        //udp隧道超时时间
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse()
        //如果keygen大于0则生成随机密钥
	if flags.Keygen > 0 {
                //key(密钥)是一个byte类型的切片
		key := make([]byte, flags.Keygen)
                //io包控制读写，ReadFull将从Reader(随机数)中读取的数据存入key中
		io.ReadFull(rand.Reader, key)
                //打印经过EncodeTostring的key
		fmt.Println(base64.URLEncoding.EncodeToString(key))
		return
	}
        //如果参数设置错误则直接返回
	if flags.Client == "" && flags.Server == "" {
		flag.Usage()
		return
	}
        //key不为空时则将其解码
	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}
        //client不为空启用client模式
	if flags.Client != "" { // client mode
                //取出connect地址
		addr := flags.Client
                //加密方式
		cipher := flags.Cipher
                //密码
		password := flags.Password
		var err error
                //判断参数格式是否以ss://开头
		if strings.HasPrefix(addr, "ss://") {
                        //解析URL格式
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}
 
		udpAddr := addr
                //选择加密方式
		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}
                //启用插件
		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, false)
			if err != nil {
				log.Fatal(err)
			}
		}
                //启用通道
		if flags.UDPTun != "" {
                        //strings.split用分隔符将字符串分离，并不包括分隔符，返回是string类型的切片
			for _, tun := range strings.Split(flags.UDPTun, ",") {
                                //再次用strings.split方法切割字符串
				p := strings.Split(tun, "=")
                                //启用goroutine
				go udpLocal(p[0], udpAddr, p[1], ciph.PacketConn)
			}
		}
                //启用通道
		if flags.TCPTun != "" {
                        //用strings.split函数分离string，不包括分隔符
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
                                //启用goroutine
				go tcpTun(p[0], addr, p[1], ciph.StreamConn)
			}
		}
                //启用socks模式
		if flags.Socks != "" {
                        //socks udp支持
			socks.UDPEnabled = flags.UDPSocks
                        //启用goroutine
			go socksLocal(flags.Socks, addr, ciph.StreamConn)
                        //是否启用udp socks
			if flags.UDPSocks {
				go udpSocksLocal(flags.Socks, udpAddr, ciph.PacketConn)
			}
		}
                //是否启用redirect重定向
		if flags.RedirTCP != "" {
			go redirLocal(flags.RedirTCP, addr, ciph.StreamConn)
		}

		if flags.RedirTCP6 != "" {
			go redir6Local(flags.RedirTCP6, addr, ciph.StreamConn)
		}
	}
        //启用 server
	if flags.Server != "" { // server mode
                //提取address，cipher，password
		addr := flags.Server
		cipher := flags.Cipher
		password := flags.Password
		var err error
                //判断参数是否以ss://开头
		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		udpAddr := addr
                //是否启用插件
		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, true)
			if err != nil {
				log.Fatal(err)
			}
		}
                //选择加密模式
		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}
                //是否启用UDP or TCP支持，udp默认值是false
		if flags.UDP {
			go udpRemote(udpAddr, ciph.PacketConn)
		}
		if flags.TCP {
			go tcpRemote(addr, ciph.StreamConn)
		}
	}
        //创建一个channel，类型为os.Signal,缓冲区大学南路为1
	sigCh := make(chan os.Signal, 1)
        //监听系统信号
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	killPlugin()
}

func parseURL(s string) (addr, cipher, password string, err error) {
       //url.Parse方法将string类型的URL解析为URL类型的数据
	u, err := url.Parse(s)
	if err != nil {
		return
	}
        //address为URL中的host地址
	addr = u.Host
	if u.User != nil {
                //cipher加密方式为用户名称
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
