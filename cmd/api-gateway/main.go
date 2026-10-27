package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	apigateway "github.com/aeitron/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = os.Getenv("AEITRON_GATEWAY_PORT")
	}
	if port == "" {
		port = "8000"
	}

	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	jwtSecret := os.Getenv("AEITRON_JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "aeitron-dev-insecure-secret-key-32bytes-min"
	}

	gw := apigateway.NewAPIGateway(jwtSecret)

	addr := fmt.Sprintf("%s:%s", host, port)
	server := &http.Server{
		Addr:         addr,
		Handler:      gw,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[aeitron-api-gateway] starting unified edge routing proxy on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[aeitron-api-gateway] server error: %v", err)
		}
	}()

	<-stopChan
	log.Println("[aeitron-api-gateway] shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[aeitron-api-gateway] shutdown warning: %v", err)
	}

	log.Println("[aeitron-api-gateway] server stopped")
}
