package main

import (
	"flag"
	"go-jlu-drcom-client/conf"
	"os"
	"os/signal"
	"syscall"
	"log"
	"go-jlu-drcom-client/service"
	"go-jlu-drcom-client/controller"
)

func main() {
	flag.Parse()
	if err := conf.Init(); err != nil {
		panic(err)
	}
	// signal handler
	log.Printf("go-jlu-drcom-client [version: %s] start", conf.Conf.Version)
	svr := service.New(conf.Conf)
	controller.Init(svr)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT, syscall.SIGSTOP)
	for {
		s := <-c
		log.Printf("go-jlu-drcom-client get a signal %s", s.String())
		switch s {
		case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGSTOP, syscall.SIGINT:
			log.Printf("go-jlu-drcom-client [version: %s] exit", conf.Conf.Version)
			return
		case syscall.SIGHUP:
		default:
			return
		}
	}
}
