package controller

import (
	"log"
	"time"
)

func start() (err error) {
	log.Println("challenge ...")
	if err = svc.Challenge(svc.ChallengeTimes); err != nil {
		log.Printf("drcomSvc.Challenge(%d) error(%v)", svc.ChallengeTimes, err)
		return
	}
	svc.ChallengeTimes++
	log.Println("ok")
	log.Println("login ...")
	if err = svc.Login(); err != nil {
		log.Printf("drcomSvc.Login() error(%v)", err)
		return
	}
	log.Println("ok")
	count := 0
	for {
		count++
		log.Printf("keep-alive ... %d", count)
		if err = svc.Alive(); err != nil {
			log.Printf("drcomSvc.Alive() error(%v)", err)
			return
		}
		log.Println("ok")
		time.Sleep(time.Second * 20)
	}
	return
}
