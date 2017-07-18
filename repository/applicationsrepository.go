package repository

import (
	"database/sql"
	"log"
)

// ValidateClientID - Validates the clientID.
func ValidateClientID(clientID string) (bool, error) {

	var count int
	err := db.QueryRow(`SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
						SELECT COUNT(1) FROM Applications WHERE ApplicationKey = ? AND IsEnabled = 1;`, clientID).Scan(&count)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		log.Println("ValidateClientID:", err)
		return false, err
	}

	return (count > 0), nil
}

// ValidateClientCredentials - Validates the client credentials.
func ValidateClientCredentials(clientID string, secretKey string) (bool, error) {

	var count int
	err := db.QueryRow(`SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
						SELECT COUNT(1) FROM Applications WHERE ApplicationKey = ? AND SecretKey = ? AND IsEnabled = 1;`, clientID, secretKey).Scan(&count)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		log.Println("ValidateClientCredentials:", err)
		return false, err
	}

	return (count > 0), nil
}
