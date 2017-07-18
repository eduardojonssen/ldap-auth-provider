package configuration

import (
	"fmt"
	"log"
	"os"

	"github.com/namsral/flag"
)

const (
	// ErrorConfigurationRequired - A mandatory configuration is not present.
	ErrorConfigurationRequired = "This is a required configuration. Please provide a value."
)

func init() {
	config := new(Configuration)

	fs := flag.NewFlagSetWithEnvPrefix(os.Args[0], "LDAP_AUTH_PROVIDER", 0)
	fs.StringVar(&config.LDAPResolutionName, "resolution_name", "", "The ldap server resolution name")
	fs.IntVar(&config.APIPort, "api_port", 19000, "The API listening port number")
	fs.StringVar(&config.DatabaseConnection, "database_connection", "", "Database connection string")

	var mock bool
	fs.BoolVar(&mock, "mock", false, "Should mock env vars")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(fmt.Sprintf("Error parsing variables %#v", err))
	}

	if mock == true {
		fmt.Println("Running under go test")
		config.LDAPResolutionName = "MOCK"
		config.DatabaseConnection = "MOCK"
	}

	errs := config.validate()
	if len(errs) > 0 {
		fmt.Println()
		for _, err := range errs {
			fmt.Println(err)
		}
		log.Fatal(fmt.Sprintf("Found %d errors while reading the environment configuration.\n\n", len(errs)))
	}

	setInstance(config)
}

var configurationInstance *Configuration

// Instance - Gets the application configuration instance.
func Instance() *Configuration {
	return configurationInstance
}

func setInstance(i *Configuration) {
	configurationInstance = i
}

// Configuration - Represents the ldap configuration settings.
type Configuration struct {
	LDAPResolutionName string
	APIPort            int
	DatabaseConnection string
}

func (conf *Configuration) validate() []error {

	var errs []error

	if conf.LDAPResolutionName == "" {
		errs = append(errs, fmt.Errorf("%s - %s", "resolution_name", ErrorConfigurationRequired))
	}

	if conf.DatabaseConnection == "" {
		errs = append(errs, fmt.Errorf("%s - %s", "database_connection", ErrorConfigurationRequired))
	}

	return errs
}
