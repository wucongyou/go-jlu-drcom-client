package service

import (
	"crypto/md5"
	"errors"
	"fmt"
	"go-jlu-drcom-client/conf"
	"hash"
	"log"
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
	result = s.md5Ctx.Sum(s.md5a)
	s.md5Ctx.Reset()
	return
}

func (s *Service) getMac() (result []byte, err error) {
	// check mac
	as := strings.Replace(s.conf.Mac, ":", "", -1)
	if len(as) != 12 {
		err = errors.New("mac length is not correct")
	}
	result = make([]byte, 6, 6)
	for i := 0; i < 12; i += 2 {
		var v uint64
		if v, err = strconv.ParseUint(as[i:i+2], 16, 8); err != nil {
			log.Printf("strconv.ParseUint(%v, 16, 8) error(%v)", as[i:i+2], err)
		}
		result = append(result, byte(v))
	}
	return
}
