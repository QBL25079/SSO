package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/QBL25079/SSO/internal/app/grpc"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL time.Duration) *App {

	grpcApp := grpcapp.New(log, grpcPort, nil)

	return &App{GRPCServer: grpcApp}
}
