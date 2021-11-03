package main

import (
	"fmt"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/hands8142/go-jwt/controllers"
	"github.com/hands8142/go-jwt/database"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file")
	}

	database.Connect()

	app := fiber.New()

	app.Use(logger.New())

	controllers.Setup(app)

	app.Listen(fmt.Sprintf(":%s", os.Getenv("PORT")))
}
