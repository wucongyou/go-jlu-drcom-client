package controller

import "log"

func start() (err error) {
	var (
		challengeTimes = 0
	)
	if err = drcomSvc.Challenge(challengeTimes); err != nil {
		log.Printf("drcomSvc.challenge(%d) error(%v)", challengeTimes, err)
		return
	}
	return
}
