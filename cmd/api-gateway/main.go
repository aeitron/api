package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	isProd := os.Getenv("AEITRON_ENV") == "production" || os.Getenv("AEITRON_DEV_MODE") == "false"

	if jwtSecret == "" {
		if isProd {
			log.Fatalf("[FATAL] AEITRON_JWT_SECRET environment variable is missing or empty. In production mode (AEITRON_ENV=%s, AEITRON_DEV_MODE=%s), the gateway fails closed. You must provide a secure secret of at least 32 bytes.", os.Getenv("AEITRON_ENV"), os.Getenv("AEITRON_DEV_MODE"))
		}
		// In development mode, NEVER use a fixed predictable secret string that attackers can forge tokens with!
		// Generate an ephemeral cryptographically random 32-byte secret for this session.
		randomSecretBytes := make([]byte, 32)
		if _, err := rand.Read(randomSecretBytes); err != nil {
			log.Fatalf("[FATAL] Failed to generate secure random secret: %v", err)
		}
		jwtSecret = hex.EncodeToString(randomSecretBytes)
		log.Printf("[SECURITY WARNING] AEITRON_JWT_SECRET was not provided. An ephemeral random 32-byte secret has been generated for this session. Tokens will not survive process restarts. Configure AEITRON_JWT_SECRET for persistent tokens.")
	} else if len(jwtSecret) < 32 {
		if isProd {
			log.Fatalf("[FATAL] AEITRON_JWT_SECRET is insufficiently random (length %d bytes < minimum required 32 bytes). In production, the gateway fails closed.", len(jwtSecret))
		}
		log.Printf("[SECURITY WARNING] AEITRON_JWT_SECRET is shorter than 32 bytes (%d bytes). Upgrade to at least 32 bytes.", len(jwtSecret))
	} else if isProd && jwtSecret == "aeitron-dev-insecure-secret-key-32bytes-min" {
		log.Fatalf("[FATAL] Insecure default development secret detected in production environment. Refusing to start.")
	}

	gw := apigateway.NewAPIGateway(jwtSecret)

	// In production, validate durable audit storage fail-fast before serving traffic
	if isProd {
		if err := gw.AuditSpooler().ValidateDurableStorage(); err != nil {
			log.Fatalf("[FATAL] Durable audit storage validation failed: %v. In production, durable audit logging is mandatory.", err)
		}
	}

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

	gw.Close()

	log.Println("[aeitron-api-gateway] server stopped")
}
