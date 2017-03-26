package controller

import (
	"go-jlu-drcom-client/service"
	"log"
)

var (
	drcomSvc *service.Service
)

func Init(s *service.Service) {
	log.Print("init controller\n")
	drcomSvc = s
	start()
}
