package controllers

import (
	"github.com/gofiber/fiber/v2"
	jwtware "github.com/gofiber/jwt/v3"
	"github.com/hands8142/go-jwt/services"
)

func Setup(app *fiber.App) {
	apiRouter := app.Group("/api")
	ApiRoute(apiRouter)
}

func ApiRoute(apiRouter fiber.Router) {
	apiRouter.Post("/register", services.Register)
	apiRouter.Post("/login", services.Login)
	apiRouter.Use(jwtware.New(jwtware.Config{
		SigningKey: []byte(services.SecretKey),
	}))
	apiRouter.Get("/user", services.User)
}
