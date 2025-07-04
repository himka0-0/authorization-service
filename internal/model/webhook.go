package model

type Webhook struct {
	GuID    string `json:"guID"`
	Message string `json:"text"`
	NewIP   string `json:"new_ip"`
}
