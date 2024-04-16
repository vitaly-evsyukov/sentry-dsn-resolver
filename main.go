package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

const timeout = time.Second * 100

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}

	baseUrl, ok := os.LookupEnv("SENTRY_BASE_URL")
	if !ok {
		log.Fatal("SENTRY_BASE_URL environment variable not set")
	}

	dr := NewDSN(http.DefaultClient, baseUrl)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dsn, err := dr.Get(ctx)
	if err != nil {
		log.Fatalf("Error getting DSN: %s", err)
	}

	log.Printf("DSN: %s", dsn)
}
