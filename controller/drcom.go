package controller

import (
	"log"
	"time"
)

func alive(c chan int) (err error) {
	count := 0
	for {
		select {
		case _, ok := <-c:
			if !ok {
				log.Println("keep-alive goroutine get a logout signal, exit")
				return
			}
		default:
		}
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
