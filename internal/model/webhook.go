package model

type Webhook struct {
	Message string `json:"text"`
	NewIP   string `json:"new_ip"`
}
