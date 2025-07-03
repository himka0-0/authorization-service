package repository

import (
	"MEDODS/internal/model"
	"gorm.io/gorm"
)

type RefreshTokenRepo struct {
	db *gorm.DB
}

func NewRefreshTokenRepo(db *gorm.DB) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}
func (r *RefreshTokenRepo) Save(token *model.RefreshToken) error {
	return r.db.Create(token).Error
}
