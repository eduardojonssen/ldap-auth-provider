package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/eduardojonssen/ldap-auth-provider/configuration"
	"github.com/eduardojonssen/ldap-auth-provider/repository"
	"github.com/gorilla/mux"
)

var (
	config *configuration.Configuration
)

type tokenEndpointRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
	Scope        string `json:"scope"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

type tokenEndpointResponse struct {
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	State        string `json:"state,omitempty"`
}

func authorizeEndpoint(w http.ResponseWriter, r *http.Request) {

	vals := r.URL.Query()

	responseType, success := vals["response_type"]
	if success == false {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	clientID, success := vals["client_id"]
	if success == false {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	scope, success := vals["scope"]
	if success == false {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	redirectURI, success := vals["redirect_uri"]
	state, success := vals["state"]

	// Validate the clientID.
	isValidClientID, err := repository.ValidateClientID(clientID[0])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if isValidClientID == false {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO: Load the redirectURI, if not specified.

	// TODO: Create an authorization code.
	// TODO: Return the state, if specified.

	log.Println(clientID, scope, redirectURI, state)

	switch responseType[0] {
	case "code":
		grantCode(w, r)
	case "token":
		grantImplicit()
	}
}

func tokenEndpoint(w http.ResponseWriter, r *http.Request) {

	decoder := json.NewDecoder(r.Body)
	var request tokenEndpointRequest
	err := decoder.Decode(&request)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer r.Body.Close()

	// Validates the grant type.
	if request.GrantType == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get and split the authorization header.
	authorizationHeader := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

	if len(authorizationHeader) == 2 && strings.ToLower(authorizationHeader[0]) == "basic" {

		// Decode the base64 credentials string.
		credentialsString, err := base64.StdEncoding.DecodeString(authorizationHeader[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Splits the clientId and clientSecret.
		credentials := strings.SplitN(string(credentialsString), ":", 2)
		if len(credentials) != 2 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		request.ClientID = credentials[0]
		request.ClientSecret = credentials[1]

	} else {

		// Validates the client id from body.
		if request.ClientID == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Validates the client secret from body.
		if request.ClientSecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	// Validate the client credentials.
	isValidClientID, err := repository.ValidateClientCredentials(request.ClientID, request.ClientSecret)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if isValidClientID == false {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Println(request)

	var response *tokenEndpointResponse

	switch request.GrantType {
	case "authorization_code":
		response, err = grantAuthorizationCode(w, &request)
	case "password":
		response, err = grantResourceOwner(w, &request)
	case "client_credentials":
		response, err = grantClientCredentials(w, &request)
	case "refresh_token":
		response, err = grantRefreshToken(w, &request)
	}

	json, err := json.Marshal(response)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func grantCode(w http.ResponseWriter, r *http.Request) {

	log.Println("authorization code requested")
}

func grantImplicit() error {

	log.Println("implicit token requested")

	return nil
}

func grantAuthorizationCode(w http.ResponseWriter, request *tokenEndpointRequest) (*tokenEndpointResponse, error) {

	log.Println("authorization token requested")

	var response = new(tokenEndpointResponse)

	response.AccessToken = "New access token"
	response.ExpiresIn = 3600
	response.RefreshToken = "New refresh token"
	response.TokenType = "Bearer"

	return response, nil
}

func grantResourceOwner(w http.ResponseWriter, request *tokenEndpointRequest) (*tokenEndpointResponse, error) {

	log.Println("resource owner token requested")

	// Checks if the username was provided.
	if request.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		return nil, nil
	}

	// Checks if the password was provided.
	if request.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return nil, nil
	}

	// TODO: to validate user credentials in database.

	return nil, nil
}

func grantClientCredentials(w http.ResponseWriter, request *tokenEndpointRequest) (*tokenEndpointResponse, error) {

	log.Println("client credentials token requested")

	return nil, nil
}

func grantRefreshToken(w http.ResponseWriter, request *tokenEndpointRequest) (*tokenEndpointResponse, error) {

	log.Println("refresh token requested")

	return nil, nil
}

func main() {
	config = configuration.Instance()

	router := mux.NewRouter()
	router.HandleFunc("/oauth2/authorize", authorizeEndpoint).Methods("GET")
	router.HandleFunc("/oauth2/token", tokenEndpoint).Methods("POST")

	http.Handle("/", router)

	log.Printf("LDAP-AUTH-API: Listening on port %d\n", config.APIPort)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.APIPort), http.DefaultServeMux))
}
