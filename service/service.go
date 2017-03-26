package service

import (
	"crypto/md5"
	"errors"
	"fmt"
	"go-jlu-drcom-client/conf"
	"hash"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
)

var (
	keepAliver = [2]byte{0xdc, 0x02}
)

type Service struct {
	conf           *conf.Config
	md5Ctx         hash.Hash
	challengeTimes int
	salt           []byte // [4:8]
	clientIp       []byte // [20:24]
	md5a           []byte
	tail1          []byte
	tail2          []byte
	count          int
	conn           *net.UDPConn
}

// New create service instance and return.
func New(c *conf.Config) (s *Service) {
	s = &Service{
		conf:           c,
		md5Ctx:         md5.New(),
		md5a:           make([]byte, 16),
		tail1:          make([]byte, 16),
		tail2:          make([]byte, 4),
		clientIp:       make([]byte, 4),
		salt:           make([]byte, 4),
		challengeTimes: 0,
		count:          0,
	}
	var (
		udpAddr *net.UDPAddr
		err     error
	)
	if udpAddr, err = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%s", c.AuthServer, c.Port)); err != nil {
		log.Fatal("failed to resolve udp address, ", err)
	}
	s.conn, err = net.DialUDP("udp", nil, udpAddr)
	return
}

// Close dao
func (s *Service) Close() {
	s.conn.Close()
	return
}

func (s *Service) md5(items ...[]byte) (result []byte) {
	for _, v := range items {
		s.md5Ctx.Write(v)
	}
	result = s.md5Ctx.Sum(nil)
	s.md5Ctx.Reset()
	return
}

func (s *Service) encrypt() (result []byte) {
	s.md5Ctx.Write([]byte{CODE, TYPE})
	s.md5Ctx.Write(s.salt)
	s.md5Ctx.Write([]byte(s.conf.Password))
	result = s.md5Ctx.Sum(nil)
	copy(s.md5a, result)
	log.Printf("s.md5a: %v, result: %v\n", s.md5a, result)
	s.md5Ctx.Reset()
	return
}

func (s *Service) mac() (result []byte, err error) {
	// check mac
	as := strings.Replace(s.conf.Mac, ":", "", -1)
	if len(as) != 12 {
		err = errors.New("mac length is not correct")
	}
	result = make([]byte, 0)
	for i := 0; i < 12; i += 2 {
		var v uint64
		if v, err = strconv.ParseUint(as[i:i+2], 16, 8); err != nil {
			log.Printf("strconv.ParseUint(%v, 16, 8) error(%v)", as[i:i+2], err)
		}
		result = append(result, byte(v))
	}
	return
}

func (s *Service) ror(md5a, password []byte) (result []byte) {
	l := len(password)
	result = make([]byte, l)
	for i := 0; i < l; i++ {
		x := md5a[i] ^ password[i]
		result[i] = (byte)((x << 3) + (x >> 5))
	}
	return
}

var (
	_y = big.NewInt(1968)
	_z = big.NewInt(int64(0xffffffff))
)

func (s *Service) checkSum(data []byte) (ret []byte) {
	// 1234 = 0x_00_00_04_d2
	sum := []byte{0x00, 0x00, 0x04, 0xd2}
	length := len(data)
	i := 0
	//0123_4567_8901_23
	for ; i+3 < length; i = i + 4 {
		//abcd ^ 3210
		//abcd ^ 7654
		//abcd ^ 1098
		sum[0] ^= data[i+3]
		sum[1] ^= data[i+2]
		sum[2] ^= data[i+1]
		sum[3] ^= data[i]
	}
	if i < length {
		//剩下_23
		//i=12,len=14
		tmp := make([]byte, 4)
		for j := 3; j >= 0 && i < length; j-- {
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
	x.SetBytes(sum)
	x.Mul(x, _y)
	x.Add(x, _z)
	tmpBytes := x.Bytes()
	length = len(tmpBytes)
	i = 0
	ret = make([]byte, 4)
	for j := length - 1; j >= 0 && i < 4; j-- {
		ret[i] = tmpBytes[j]
		i++
	}
	return
}