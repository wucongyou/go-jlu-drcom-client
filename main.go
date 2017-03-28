package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go-jlu-drcom-client/conf"
	"go-jlu-drcom-client/controller"
	"go-jlu-drcom-client/service"
)

func main() {
	flag.Parse()
	if err := conf.Init(); err != nil {
		panic(err)
	}
	x := make(chan int)
	c := make(chan os.Signal, 1)
	svr := service.New(conf.Conf)
	controller.Init(svr, x)
	log.Printf("go-jlu-drcom-client [version: %s] start", conf.Conf.Version)
	// signal handler
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT, syscall.SIGSTOP)
	for {
		select {
		case _, ok := <-x:
			if !ok {
				log.Println("go-jlu-drcom-client terminated cause internal error")
				controller.Close()
				return
			}
		case s := <-c:
			log.Printf("go-jlu-drcom-client get a signal %s", s.String())
			switch s {
			case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGSTOP, syscall.SIGINT:
				log.Printf("go-jlu-drcom-client [version: %s] exit", conf.Conf.Version)
				controller.Close()
				return
			case syscall.SIGHUP:
			default:
				return
			}
		}
	}
}
