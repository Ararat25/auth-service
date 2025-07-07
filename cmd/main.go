package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/Ararat25/auth-service/config"
	_ "github.com/Ararat25/auth-service/docs"
	"github.com/Ararat25/auth-service/internal/controller"
	"github.com/Ararat25/auth-service/internal/database"
	middle "github.com/Ararat25/auth-service/internal/middleware"
	"github.com/Ararat25/auth-service/internal/model"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
)

const configPath = "config.yml" // путь до файла конфигурации

// @title Auth Service API
// @version 1.0
// @description This is an authentication service with JWT
// @host localhost:8080
// @BasePath /
func main() {
	handler, conf := initApp()

	r := initRouter(handler)

	hostPort := fmt.Sprintf("%s:%d", conf.Server.Host, conf.Server.Port)

	log.Printf("Server starting on %s", hostPort)
	err := http.ListenAndServe(hostPort, r)
	if err != nil {
		log.Fatalf("Start server error: %s", err.Error())
	}
}

// initApp инициализирует конфигурацию, подключение к базе данных и сервисы приложения
func initApp() (*controller.Handler, *config.Config) {
	err := config.LoadEnvVariables()
	if err != nil {
		log.Fatalf("error loading env variables: %v\n", err)
	}

	tokenSalt, dbHost, dbUser, dbPassword, dbName, dbPortString :=
		os.Getenv("TOKEN_SALT"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT")

	if tokenSalt == "" || dbHost == "" || dbUser == "" || dbPassword == "" || dbName == "" || dbPortString == "" {
		log.Fatalln("not all environment variables are set")
	}

	dbPort, _ := strconv.Atoi(dbPortString)

	conf, err := config.NewConfig(configPath)
	if err != nil {
		log.Fatalf("error loading config file: %v\n", err)
	}

	err = database.ConnectDB(dbHost, dbUser, dbPassword, dbName, dbPort)
	if err != nil {
		log.Fatalf("error connecting to database: %v\n", err)
	}

	authService := model.NewAuthService([]byte(tokenSalt), conf.Server.AccessTokenTTl, conf.Server.RefreshTokenTTl, database.DB.Db)

	handler := controller.NewHandler(authService)

	return handler, conf
}

// initRouter настраивает маршруты и middleware для сервера
func initRouter(handler *controller.Handler) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middle.JsonHeader)

	r.Get("/api/docs/*", httpSwagger.WrapHandler)
	r.Get("/api/tokens", handler.GetTokens)
	r.Post("/api/refresh", handler.RefreshToken)
	r.Post("/api/me", handler.GetGUID)
	r.Post("/api/logout", handler.Logout)

	return r
}
