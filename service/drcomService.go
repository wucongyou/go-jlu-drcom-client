package service

import (
	"errors"
	"log"
	"math/rand"
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
	cRecv := make([]byte, 76)
	if _, err = conn.Read(cRecv); err != nil {
		log.Printf("conn.Read() error(%v)", err)
		return
	}
	if cRecv[0] == 0x02 {
		s.salt = cRecv[4:8]
		s.clientIp = cRecv[20:24]
		return
	}
	log.Printf("recv: %v", cRecv)
	err = errors.New("reveive head is not correct")
	return
}

const (
	CODE          = byte(0x03)
	TYPE          = byte(0x01)
	EOF           = byte(0x00)
	CONTROL_CHECK = byte(0x20)
	ADAPTER_NUM   = byte(0x05)
	IP_DOG        = byte(0x01)
)

var (
	_emptyIp    = []byte{0x00, 0x00, 0x00, 0x00}
	_primaryDns = []byte{10, 10, 10, 10}
	_dhcpServer = []byte{0, 0, 0, 0}
)

func (s *Service) Login() (err error) {
	buf := make([]byte, 334)
	pwdLen := len(s.conf.Password)
	if pwdLen > 16 {
		pwdLen = 16
	}
	buf = append(buf, CODE, TYPE, EOF,
		byte(len(s.conf.Username)+20))
	buf = append(buf, s.encrypt()...)
	user := make([]byte, 36, 36)
	copy(user, []byte(s.conf.Username))
	buf = append(buf, user...)
	buf = append(buf, CONTROL_CHECK, ADAPTER_NUM)
	// md5a xor mac
	mac := make([]byte, 6, 6)
	for i := 0; i < 6; i++ {
		mac[i] = mac[i] ^ s.md5a[i]
	}
	buf = append(buf, mac...)
	// md5b
	buf = append(buf, s.md5([]byte{0x01}, []byte(s.conf.Password), []byte(s.salt), []byte{0x00, 0x00, 0x00, 0x00})...)
	buf = append(buf, byte(0x01))
	buf = append(buf, s.clientIp...)
	for i := 0; i < 3; i++ {
		buf = append(buf, _emptyIp...)
	}
	// md5c
	tmp := make([]byte, len(buf)+4)
	copy(tmp, buf)
	tmp = append(tmp, []byte{0x14, 0x00, 0x07, 0x0b}...)
	buf = append(buf, s.md5(tmp)...)
	return
}
