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
func (r *RefreshTokenRepo) GetByID(id string) (*model.RefreshToken, error) {
	var token model.RefreshToken
	if err := r.db.Where("id = ?", id).First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}
func (r *RefreshTokenRepo) DeleteAllByUserGUID(guid string) error {
	return r.db.Delete(&model.RefreshToken{}, "user_guid = ?", guid).Error
}
func (r *RefreshTokenRepo) ChangUsage(id string) error {
	return r.db.Model(&model.RefreshToken{}).
		Where("id = ?", id).
		Update("used", true).Error
}
