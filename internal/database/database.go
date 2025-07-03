package database

import (
	"fmt"
	"github.com/Ararat25/auth-service/internal/entity"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
)

type Dbinstance struct {
	Db *gorm.DB
}

var DB Dbinstance

func ConnectDB(dbUser string, dbPassword string, dbName string, dbPort int) {
	dsn := fmt.Sprintf(
		"host=db user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=Europe/Moscow",
		dbUser,
		dbPassword,
		dbName,
		dbPort,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})

	if err != nil {
		log.Fatal("Failed to connect to database.\n", err)
	}

	log.Println("connected to database")
	db.Logger = logger.Default.LogMode(logger.Info)

	log.Println("running migration database")
	err = db.AutoMigrate(&entity.Session{})
	if err != nil {
		return
	}

	DB = Dbinstance{
		Db: db,
	}
}
