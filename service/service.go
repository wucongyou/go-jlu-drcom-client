package service

import (
	"crypto/md5"
	"errors"
	"fmt"
	"hash"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"

	"go-jlu-drcom-client/conf"
)

const (
	_codeIn       = byte(0x03)
	_codeOut      = byte(0x06)
	_type         = byte(0x01)
	_eof          = byte(0x00)
	_controlCheck = byte(0x20)
	_adapterNum   = byte(0x05)
	_ipDog        = byte(0x01)
)

var (
	_delimiter   = []byte{0x00, 0x00, 0x00, 0x00}
	_emptyIP     = []byte{0, 0, 0, 0}
	_primaryDNS  = []byte{10, 10, 10, 10}
	_dhcpServer  = []byte{0, 0, 0, 0}
	_authVersion = []byte{0x6a, 0x00}
	_magic1      = big.NewInt(1968)
	_magic2      = big.NewInt(int64(0xffffffff))
	_magic3      = big.NewInt(int64(711))
)

type Service struct {
	conf           *conf.Config
	md5Ctx         hash.Hash
	salt           []byte // [4:8]
	clientIP       []byte // [20:24]
	md5a           []byte
	tail1          []byte
	tail2          []byte
	keepAliveVer   []byte // [28:30]
	conn           *net.UDPConn
	ChallengeTimes int
	Count          int
}

// New create service instance and return.
func New(c *conf.Config) (s *Service) {
	s = &Service{
		conf:           c,
		md5Ctx:         md5.New(),
		md5a:           make([]byte, 16),
		tail1:          make([]byte, 16),
		tail2:          make([]byte, 4),
		keepAliveVer:   []byte{0xdc, 0x02},
		clientIP:       make([]byte, 4),
		salt:           make([]byte, 4),
		ChallengeTimes: 0,
		Count:          0,
	}
	var (
		err     error
		udpAddr *net.UDPAddr
	)
	if udpAddr, err = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%s", c.AuthServer, c.Port)); err != nil {
		log.Fatalf("net.ResolveUDPAddr(udp4, %s) error(%v) ", fmt.Sprintf("%s:%s", c.AuthServer, c.Port), err)
	}
	if s.conn, err = net.DialUDP("udp", nil, udpAddr); err != nil {
		log.Fatalf("net.DialUDP(udp, %v, %v) error(%v)", nil, udpAddr, err)
	}
	return
}

// Close service.
func (s *Service) Close() {
	s.conn.Close()
	return
}

func (s *Service) md5(items ...[]byte) (ret []byte) {
	for _, v := range items {
		s.md5Ctx.Write(v)
	}
	ret = s.md5Ctx.Sum(nil)
	s.md5Ctx.Reset()
	return
}

func (s *Service) mac() (ret []byte, err error) {
	// check mac
	as := strings.Replace(s.conf.Mac, ":", "", -1)
	if len(as) != 12 {
		err = errors.New("length of mac address is not correct")
	}
	ret = make([]byte, 0, 6)
	for i := 0; i < 12; i += 2 {
		var v uint64
		if v, err = strconv.ParseUint(as[i:i+2], 16, 8); err != nil {
			log.Printf("strconv.ParseUint(%v, 16, 8) error(%v)", as[i:i+2], err)
			ret = nil
			return
		}
		ret = append(ret, byte(v))
	}
	return
}

func (s *Service) ror(md5a, password []byte) (ret []byte) {
	l := len(password)
	ret = make([]byte, l)
	for i := 0; i < l; i++ {
		x := md5a[i] ^ password[i]
		ret[i] = (byte)((x << 3) + (x >> 5))
	}
	return
}

func (s *Service) checkSum(data []byte) (ret []byte) {
	// 1234 = 0x_00_00_04_d2
	sum := []byte{0x00, 0x00, 0x04, 0xd2}
	l := len(data)
	i := 0
	//0123_4567_8901_23
	for ; i+3 < l; i = i + 4 {
		//abcd ^ 3210
		//abcd ^ 7654
		//abcd ^ 1098
		sum[0] ^= data[i+3]
		sum[1] ^= data[i+2]
		sum[2] ^= data[i+1]
		sum[3] ^= data[i]
	}
	if i < l {
		//剩下_23
		//i=12,len=14
		tmp := make([]byte, 4)
		for j := 3; j >= 0 && i < l; j-- {
			//j=3 tmp = 0 0 0 2  i=12  13
			//j=2 tmp = 0 0 3 2  i=13  14
			tmp[j] = data[i]
			i++
		}
		for j := 0; j < 4; j++ {
			sum[j] ^= tmp[j]
		}
	}
	var x = big.NewInt(int64(0))
	tmpBytes := x.SetBytes(sum).Mul(x, _magic1).Add(x, _magic2).Bytes()
	l = len(tmpBytes)
	i = 0
	ret = make([]byte, 4)
	for j := l - 1; j >= 0 && i < 4; j-- {
		ret[i] = tmpBytes[j]
		i++
	}
	return
}

func (s *Service) extra() bool {
	return s.Count%21 == 0
}

func (s *Service) crc(buf []byte) (ret []byte) {
	sum := make([]byte, 2)
	l := len(buf)
	for i := 0; i < l-1; i += 2 {
		sum[0] ^= buf[i+1]
		sum[1] ^= buf[i]
	}
	x := big.NewInt(int64(0))
	tmpBytes := x.SetBytes(sum).Mul(x, _magic3).Bytes()
	ret = make([]byte, 4)
	l = len(tmpBytes)
	for i := 0; i < 4 && l > 0; i++ {
		l--
		ret[i] = tmpBytes[l]
	}
	return
}
