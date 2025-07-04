package service

import (
	"MEDODS/internal/model"
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func (s *AuthService) sendWebhook(newIP, guid string) {
	payload := model.Webhook{
		GuID:    guid,
		Message: "Попытка входа с нового ip",
		NewIP:   newIP,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Webhook marshal error: %v", err)
		return
	}

	webhookURL := os.Getenv("WEBHOOK_URL")
	if webhookURL == "" {
		log.Println("WEBHOOK_URL is not set")
		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("Webhook request error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("Webhook returned non-2xx status: %d", resp.StatusCode)
	}
}
