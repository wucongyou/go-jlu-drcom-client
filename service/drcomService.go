package service

import (
	"bytes"
	"errors"
	"log"
	"math/rand"
)

const (
	CODE          = byte(0x03)
	TYPE          = byte(0x01)
	EOF           = byte(0x00)
	CONTROL_CHECK = byte(0x20)
	ADAPTER_NUM   = byte(0x05)
	IP_DOG        = byte(0x01)
)

var (
	_delimeter   = []byte{0x00, 0x00, 0x00, 0x00}
	_emptyIp     = []byte{0x00, 0x00, 0x00, 0x00}
	_primaryDns  = []byte{10, 10, 10, 10}
	_dhcpServer  = []byte{0, 0, 0, 0}
	_authVersion = []byte{0x6a, 0x00}
)

func (s *Service) Challenge(tryTimes int) (err error) {
	buf := []byte{0x01, (byte)(0x02 + tryTimes),
		byte(rand.Int()), byte(rand.Int()), 0x6a,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00}
	var (
		conn = s.conn
	)
	if _, err = conn.Write(buf); err != nil {
		log.Printf("conn.Write(%v) error(%v)", buf, err)
		return
	}
	recv := make([]byte, 76)
	if _, err = conn.Read(recv); err != nil {
		log.Printf("conn.Read() error(%v)", err)
		return
	}
	if recv[0] == 0x02 {
		copy(s.salt, recv[4:8])
		copy(s.clientIp, recv[20:24])
		return
	}
	log.Printf("recv: %v", recv)
	err = errors.New("reveive head is not correct")
	return
}

func (s *Service) Login() (err error) {
	buf, err := s.buf()
	if err != nil {
		log.Printf("service.buf() error(%v)", err)
	}
	log.Printf("buf len: %d, expected: %d", len(buf), 334+(len(s.conf.Password)-1)/4*4)
	log.Printf("buf: %v\n", buf)
	log.Printf("bufStr: %s\n", string(buf))
	var (
		conn = s.conn
	)
	if _, err = conn.Write(buf); err != nil {
		log.Printf("conn.Write(%v) error(%v)", buf, err)
		return
	}
	recv := make([]byte, 128)
	if _, err = conn.Read(recv); err != nil {
		log.Printf("conn.Read() error(%v)", err)
		return
	}
	log.Printf("recv: %v", recv)
	if recv[0] != 0x04 {
		if recv[0] == 0x05 {
			if recv[4] == 0x0B {
				err = errors.New("Invalid Mac Address, please select the address registered in ip.jlu.edu.cn")
			} else {
				err = errors.New("Invalid username or password")
			}
		} else {
			err = errors.New("Failed to login, unknown error")
		}
		return
	}
	// 保存 tail1. 构造 keep38 要用 md5a(在mkptk中保存) 和 tail1
	// 注销也要用 tail1
	copy(s.tail1, recv[23:39])
	return
}

func (s *Service) buf() (buf []byte, err error) {
	buf = make([]byte, 0)
	buf = append(buf, CODE, TYPE, EOF,
		byte(len(s.conf.Username)+20)) // [0:4]
	buf = append(buf, s.encrypt()...) // [4:20]
	user := make([]byte, 36, 36)
	copy(user, []byte(s.conf.Username))
	buf = append(buf, user...)                    // [20:56]
	buf = append(buf, CONTROL_CHECK, ADAPTER_NUM) //[56:58]
	// md5a xor mac
	mac, err := s.mac()
	if err != nil {
		log.Printf("service.mac() error(%v)", err)
		return
	}
	for i := 0; i < 6; i++ {
		mac[i] = mac[i] ^ s.md5a[i]
	}
	buf = append(buf, mac...) // [58:64]
	// md5b
	md5b := s.md5([]byte{0x01}, []byte(s.conf.Password), []byte(s.salt), []byte{0x00, 0x00, 0x00, 0x00})
	buf = append(buf, md5b...)                      // [64:80]
	buf = append(buf, byte(0x01))                   // [80:81]
	buf = append(buf, s.clientIp...)                // [81:85]
	buf = append(buf, bytes.Repeat(_emptyIp, 3)...) // [85:97]
	// md5c
	tmp := make([]byte, len(buf))
	copy(tmp, buf)
	tmp = append(tmp, []byte{0x14, 0x00, 0x07, 0x0b}...)
	md5c := s.md5(tmp)
	buf = append(buf, md5c[:8]...)   // [97:105]
	buf = append(buf, IP_DOG)        // [105:106]
	buf = append(buf, _delimeter...) // [106:110]
	hostname := make([]byte, 32, 32)
	copy(hostname, []byte(s.conf.Hostname))
	buf = append(buf, hostname...)                                               // [110:142]
	buf = append(buf, _primaryDns...)                                            // [142:146]
	buf = append(buf, _dhcpServer...)                                            // [146:150]
	buf = append(buf, _emptyIp...)                                               // secondary dns, [150:154]
	buf = append(buf, bytes.Repeat(_delimeter, 2)...)                            // [154,162]
	buf = append(buf, []byte{0x94, 0x00, 0x00, 0x00}...)                         // [162,166]
	buf = append(buf, []byte{0x06, 0x00, 0x00, 0x00}...)                         // [166,170]
	buf = append(buf, []byte{0x02, 0x00, 0x00, 0x00}...)                         // [170,174]
	buf = append(buf, []byte{0xf0, 0x23, 0x00, 0x00}...)                         // [174,178]
	buf = append(buf, []byte{0x02, 0x00, 0x00, 0x00}...)                         // [178,182]
	buf = append(buf, []byte{0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0xcf, 0x07}...) // [182,190]
	buf = append(buf, byte(0x6a))                                                // [190,191]
	buf = append(buf, bytes.Repeat([]byte{0x00}, 55)...)                         // [191:246]
	exBytes := []byte{
		0x33, 0x64, 0x63, 0x37, 0x39, 0x66, 0x35, 0x32,
		0x31, 0x32, 0x65, 0x38, 0x31, 0x37, 0x30, 0x61,
		0x63, 0x66, 0x61, 0x39, 0x65, 0x63, 0x39, 0x35,
		0x66, 0x31, 0x64, 0x37, 0x34, 0x39, 0x31, 0x36,
		0x35, 0x34, 0x32, 0x62, 0x65, 0x37, 0x62, 0x31,
	}
	buf = append(buf, exBytes...)                        // [246:286]
	buf = append(buf, bytes.Repeat([]byte{0x00}, 24)...) // [286:310]
	buf = append(buf, _authVersion...)                   // [310:312]
	buf = append(buf, byte(0x00))                        // [312:313]
	pwdLen := len(s.conf.Password)
	if pwdLen > 16 {
		pwdLen = 16
	}
	buf = append(buf, byte(pwdLen)) // [313:314]
	ror := s.ror(s.md5a, []byte(s.conf.Password))
	buf = append(buf, ror[:pwdLen]...)       // [314:314+pwdLen]
	buf = append(buf, []byte{0x02, 0x0c}...) // [314+l:316+l]
	tmp = make([]byte, len(buf))
	copy(tmp, buf)
	tmp = append(tmp, []byte{0x01, 0x26, 0x07, 0x11, 0x00, 0x00}...)
	tmp = append(tmp, mac[:4]...)
	sum := s.checkSum(tmp)
	buf = append(buf, sum[:4]...)            // [316+l,320+l]
	buf = append(buf, []byte{0x00, 0x00}...) // [320+l,322+l]
	buf = append(buf, mac...)                // [322+l,328+l]
	zeroCount := (4 - pwdLen%4) % 4
	buf = append(buf, bytes.Repeat([]byte{0x00}, zeroCount)...)
	for i := 0; i < 2; i++ {
		buf = append(buf, byte(rand.Int()))
	}
	return
}
