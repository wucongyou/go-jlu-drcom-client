package service

import (
	"crypto/md5"
	"fmt"
	"hash"
	"log"
	"math/big"
	"net"
	"time"

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
	c              *conf.Config
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
	logoutCh       chan struct{}
}

// New create service instance and return.
func New(c *conf.Config) (s *Service) {
	s = &Service{
		c:              c,
		md5Ctx:         md5.New(),
		md5a:           make([]byte, 16),
		tail1:          make([]byte, 16),
		tail2:          make([]byte, 4),
		keepAliveVer:   []byte{0xdc, 0x02},
		clientIP:       make([]byte, 4),
		salt:           make([]byte, 4),
		ChallengeTimes: 0,
		Count:          0,
		logoutCh:       make(chan struct{}, 1),
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

// Start start drcom client.
func (s *Service) Start() {
	log.Println("start ...")
	log.Println("challenge ...")
	if err := s.Challenge(s.ChallengeTimes); err != nil {
		log.Printf("drcomSvc.Challenge(%d) error(%v)", s.ChallengeTimes, err)
		return
	}
	s.ChallengeTimes++
	log.Println("ok")
	log.Println("login ...")
	if err := s.Login(); err != nil {
		log.Printf("drcomSvc.Login() error(%v)", err)
		return
	}
	log.Println("ok")
	log.Println("alive daemon start ...")
	go s.aliveproc()
	log.Println("ok")
	log.Println("logout daemon start ...")
	go s.logoutproc()
	log.Println("ok")
}

func (s *Service) aliveproc() {
	count := 0
	for {
		select {
		case _, ok := <-s.logoutCh:
			if !ok {
				log.Println("keep-aliveproc goroutine get a logout signal, exit")
				return
			}
		default:
		}
		count++
		log.Printf("keep-aliveproc ... %d", count)
		if err := s.Alive(); err != nil {
			log.Printf("drcomSvc.Alive() error(%v)", err)
			time.Sleep(time.Second * 5)
			continue
		}
		log.Println("ok")
		time.Sleep(time.Second * 20)
	}
	return
}

func (s *Service) logoutproc() {
	if _, ok := <-s.logoutCh; !ok {
		log.Println("logout ...")
		if err := s.Challenge(s.ChallengeTimes); err != nil {
			log.Printf("drcomSvc.Challenge(%d) error(%v)", s.ChallengeTimes, err)
			return
		}
		s.ChallengeTimes++
		if err := s.Logout(); err != nil {
			log.Printf("service.Logout() error(%v)", err)
			return
		}
		log.Println("ok")
	}
}

// Close close service.
func (s *Service) Close() error {
	close(s.logoutCh)
	s.conn.Close()
	return nil
}
