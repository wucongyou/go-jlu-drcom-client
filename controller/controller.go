package controller

import "go-jlu-drcom-client/service"

var (
	drcomSvc *service.Service
)

func Init(s *service.Service) {
	drcomSvc = s
	start()
}
