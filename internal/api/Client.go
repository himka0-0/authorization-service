package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func MyGuid(c *gin.Context) {
	guid := c.GetString("guid")
	c.JSON(http.StatusOK, gin.H{"guid": guid})
}
