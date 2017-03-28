package controller

import (
	"log"
	"sync"

	"go-jlu-drcom-client/service"
)

var (
	wg  sync.WaitGroup
	svc *service.Service
	out = make(chan int)
)

func Init(s *service.Service, c chan int) {
	svc = s
	go func() {
		var err error
		wg.Add(1)
		defer wg.Done()
		log.Println("start ...")
		log.Println("challenge ...")
		if err = svc.Challenge(svc.ChallengeTimes); err != nil {
			log.Printf("drcomSvc.Challenge(%d) error(%v)", svc.ChallengeTimes, err)
			close(c)
			return
		}
		svc.ChallengeTimes++
		log.Println("ok")
		log.Println("login ...")
		if err = svc.Login(); err != nil {
			log.Printf("drcomSvc.Login() error(%v)", err)
			close(c)
			return
		}
		log.Println("ok")
		log.Println("alive ...")
		if err = alive(out); err != nil {
			close(c)
			return
		}
		close(c)
	}()
	go func() {
		wg.Add(1)
		defer wg.Done()
		log.Println("logout daemon ...")
		if _, ok := <-out; !ok {
			log.Println("logout ...")
			if err := svc.Challenge(svc.ChallengeTimes); err != nil {
				log.Printf("drcomSvc.Challenge(%d) error(%v)", svc.ChallengeTimes, err)
				return
			}
			svc.ChallengeTimes++
			if err := svc.Logout(); err != nil {
				log.Printf("service.Logout() error(%v)", err)
				return
			}
			log.Println("ok")
		}
	}()
}

func Close() {
	close(out)
	wg.Wait()
	log.Println("close servce ...")
	svc.Close()
	log.Println("ok")
}
