package controller

import "log"

func start() (err error) {
	var (
		challengeTimes = 0
	)
	log.Println("challenge start")
	if err = drcomSvc.Challenge(challengeTimes); err != nil {
		log.Printf("drcomSvc.Challenge(%d) error(%v)", challengeTimes, err)
		return
	}
	challengeTimes++
	log.Println("challenge ok")
	log.Println("login start")
	if err = drcomSvc.Login(); err != nil {
		log.Printf("drcomSvc.Login() error(%v)", err)
		return
	}
	log.Println("login ok")
	return
}
