package repository

import (
	"database/sql"
	"log"

	// Initializes mssql driver.
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/eduardojonssen/ldap-auth-provider/configuration"
)

var (
	db     *sql.DB
	config *configuration.Configuration
)

func init() {

	config = configuration.Instance()

	var err error

	db, err = sql.Open("mssql", config.DatabaseConnection)
	if err != nil {
		log.Panic(err)
	}
	if err = db.Ping(); err != nil {
		log.Panic(err)
	}
}
