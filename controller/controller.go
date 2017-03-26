package controller

import (
	"log"

	"go-jlu-drcom-client/service"
)

var (
	drcomSvc *service.Service
)

func Init(s *service.Service) {
	log.Print("init controller\n")
	drcomSvc = s
	start()
}
