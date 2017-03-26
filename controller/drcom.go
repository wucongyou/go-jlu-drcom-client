package controller

import (
	"log"
	"time"
)

func start() (err error) {
	log.Println("challenge start")
	if err = drcomSvc.Challenge(drcomSvc.ChallengeTimes); err != nil {
		log.Printf("drcomSvc.Challenge(%d) error(%v)", drcomSvc.ChallengeTimes, err)
		return
	}
	drcomSvc.ChallengeTimes++
	log.Println("challenge ok")
	log.Println("login start")
	if err = drcomSvc.Login(); err != nil {
		log.Printf("drcomSvc.Login() error(%v)", err)
		return
	}
	log.Println("login ok")
	count := 0
	for {
		count++
		log.Printf("keep-alive start, count: %d", count)
		if err = drcomSvc.Alive(); err != nil {
			return
		}
		log.Printf("keep-alive ok, count: %d", count)
		time.Sleep(time.Second * 20)
	}
	return
}
