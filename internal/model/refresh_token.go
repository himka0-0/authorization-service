package model

import "time"

type RefreshToken struct {
	ID        string `gorm:"primaryKey"`
	UserGUID  string `gorm:"index"`
	Hash      string
	UserAgent string
	IP        string
	Used      bool
	CreatedAt time.Time
	ExpiresAt time.Time
}
