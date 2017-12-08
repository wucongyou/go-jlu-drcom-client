package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go-jlu-drcom-client/conf"
	"go-jlu-drcom-client/service"
)

func main() {
	flag.Parse()
	if err := conf.Init(); err != nil {
		panic(err)
	}
	c := make(chan os.Signal, 1)
	svr := service.New(conf.Conf)
	svr.Start()
	log.Printf("go-jlu-drcom-client [version: %s] start", conf.Conf.Version)
	// signal handler
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	for {
		select {
		case s := <-c:
			log.Printf("go-jlu-drcom-client get a signal %s", s.String())
			switch s {
			case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
				log.Printf("go-jlu-drcom-client [version: %s] exit", conf.Conf.Version)
				svr.Close()
				return
			case syscall.SIGHUP:
			default:
				return
			}
		}
	}
}
