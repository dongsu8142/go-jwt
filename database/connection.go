package database

import (
	"fmt"
	"os"

	"github.com/hands8142/go-jwt/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	connection, err := gorm.Open(mysql.Open(fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", os.Getenv("MYSQL_DB_USERNAME"), os.Getenv("MYSQL_DB_PASSWORD"), os.Getenv("MYSQL_DB_HOST"), os.Getenv("MYSQL_DB_DATABASE"))), &gorm.Config{})

	if err != nil {
		panic("could not connect to the database")
	}

	DB = connection

	connection.AutoMigrate(&models.User{})
}
