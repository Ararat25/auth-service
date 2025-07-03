package main

import (
	"fmt"
	"github.com/Ararat25/auth-service/internal/database"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"net/http"
	"os"
)

func main() {
	database.ConnectDB(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), 5432)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	if err := http.ListenAndServe(":3000", r); err != nil {
		fmt.Printf("Start server error: %s", err.Error())
		return
	}
}
