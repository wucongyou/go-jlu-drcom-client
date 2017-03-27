package controller

import (
	"go-jlu-drcom-client/service"
)

var (
	svc *service.Service
)

func Init(s *service.Service) {
	svc = s
	start()
}
