package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/eduardojonssen/ldap-auth-provider/configuration"
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

	// TODO: Check repository connection.

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

	// TODO: Validate the clientID.
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

	// TODO: Check repository connection.

	decoder := json.NewDecoder(r.Body)
	var request tokenEndpointRequest
	err := decoder.Decode(&request)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println(request)

	defer r.Body.Close()

	// Validates the grant type.
	if request.GrantType == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// TODO: Read client credentials from Authorization header.

	// Validates the client id.
	if request.ClientID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Validates the client secret.
	if request.ClientSecret == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var response *tokenEndpointResponse

	switch request.GrantType {
	case "authorization_code":
		response, err = grantAuthorizationCode(&request)
	case "password":
		response, err = grantResourceOwner(&request)
	case "client_credentials":
		response, err = grantClientCredentials(&request)
	case "refresh_token":
		response, err = grantRefreshToken(&request)
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

func grantAuthorizationCode(request *tokenEndpointRequest) (*tokenEndpointResponse, error) {

	log.Println("authorization token requested:", request)

	var response = new(tokenEndpointResponse)

	response.AccessToken = "New access token"
	response.ExpiresIn = 3600
	response.RefreshToken = "New refresh token"
	response.TokenType = "Bearer"

	return response, nil
}

func grantResourceOwner(request *tokenEndpointRequest) (*tokenEndpointResponse, error) {

	log.Println("resource owner token requested")

	return nil, nil
}

func grantClientCredentials(request *tokenEndpointRequest) (*tokenEndpointResponse, error) {

	log.Println("client credentials token requested")

	return nil, nil
}

func grantRefreshToken(request *tokenEndpointRequest) (*tokenEndpointResponse, error) {

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
