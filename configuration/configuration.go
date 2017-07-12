package configuration

import (
	"fmt"
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

	var mock bool
	fs.BoolVar(&mock, "mock", false, "Should mock env vars")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		panic(fmt.Sprintf("Error parsing variables %#v", err))
	}

	if mock == true {
		fmt.Println("Running under go test")
		config.LDAPResolutionName = "MOCK"
	}

	errs := config.validate()
	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Println(err)
		}
		panic(fmt.Sprintf("Found %d errors while reading ehe environment configuration", len(errs)))
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
}

func (conf *Configuration) validate() []error {

	var errs []error

	if conf.LDAPResolutionName == "" {
		errs = append(errs, fmt.Errorf("%s - %s", "resolution_name", ErrorConfigurationRequired))
	}

	return errs
}
