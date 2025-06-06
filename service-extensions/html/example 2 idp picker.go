package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/strata-io/service-extension/orchestrator"
)

const (
	idrUserEndpoint              = "https://localhost:8443/api/users?email=%s"
	idrRootCAPath                = "/etc/maverics/certs/certs/rootCA.pem"
	idpFormPath                  = "/etc/maverics/html/idp-form.html"
	workrelationFormTemplatePath = "/etc/maverics/html/work-relations/workrelations-form.html"
)

// User defines the user entity from the IDR API.
type User struct {
	Id            string `json:"id"`
	Displayname   string `json:"displayname"`
	Email         string `json:"email"`
	Firstname     string `json:"firstname"`
	Lastname      string `json:"lastname"`
	Workrelations []struct {
		WrId      string   `json:"wr_id"`
		WrDisplay string   `json:"wr_display"`
		Roles     []string `json:"roles"`
	} `json:"workrelations"`
}

// IsAuthenticated determines if the user is authenticated.
func IsAuthenticated(api orchestrator.Orchestrator, rw http.ResponseWriter, req *http.Request) bool {
	log := api.Logger()
	session, err := api.Session()
	metadata := api.Metadata()
	rawIDPs := metadata["idps"]
	idps := strings.Split(rawIDPs.(string), ",")
	if err != nil {
		log.Error("msg", "failed to get session", "error", err)
		return false
	}
	log.Info("msg", "determining if user is authenticated")

	// Check if the user is authenticated through any IdP
	isAuthenticated := false
	for _, a := range idps {
		log.Debug("msg", "checking if user is authenticated to: "+a)
		authenticated, _ := session.GetString(a + ".authenticated")
		if authenticated == "true" {
			log.Info("msg", fmt.Sprintf("user is authenticated with '%s'", a))
			isAuthenticated = true
			break
		}
	}
	/*	for name := range ag.IDPs {
		authenticated := session.GetString(req, name+".authenticated")
		if authenticated == "true" {
			log.Info("msg", fmt.Sprintf("user is authenticated with '%s'", name))
			isAuthenticated = true
			break
		}

	} */
	if !isAuthenticated {
		log.Debug("msg", "user is not yet authenticated")
		return false
	}

	log.Debug("msg", "determining if the user has already selected a work relation")
	roles, err := session.GetString("idr.roles")
	if err != nil {
		log.Error("msg", "failed to get roles from session", "error", err)
		return false
	}
	if len(roles) == 0 {
		log.Info("msg", "no roles found on session")
		return false
	}

	return true
}

// Authenticate authenticates the user against the IDP that they select.
func Authenticate(api orchestrator.Orchestrator, rw http.ResponseWriter, req *http.Request) {
	log := api.Logger()
	session, _ := api.Session()
	log.Info("msg", "authenticating user")

	idpName, _ := session.GetString("idr.selectedIDP")
	idpSelected := len(idpName) != 0

	if !idpSelected && req.Method == http.MethodGet {
		renderIDPForm(api, rw)
	}

	if req.Method == http.MethodPost && req.URL.Path == "/idps" {
		log.Info("msg", "the http request method is post & the URL path is /idps")
		handleIDPSelection(api, rw, req)
	}

	if idpSelected && req.Method == http.MethodGet {
		log.Info("msg", "line 109")
		renderWorkRelationForm(idpName, rw, api)
	}

	if req.Method == http.MethodPost && req.URL.Path == "/workrelations" {
		handleWorkRelationSelection(req, rw, api)
	}
}

func renderIDPForm(api orchestrator.Orchestrator, rw http.ResponseWriter) error {
	log := api.Logger()
	/*session, _ := api.Session()*/

	metadata := api.Metadata()

	rawIDPs := metadata["idps"]
	idps := strings.Split(rawIDPs.(string), ",")

	// Read the HTML template
	assets, err := api.ServiceExtensionAssets().ReadFile("idp-form.html")
	if err != nil {
		http.Error(rw, "Could not read HTML template", http.StatusInternalServerError)
		return err
	}

	htmlTemplate := string(assets)

	var optionsBuilder strings.Builder

	for _, i := range idps {
		log.Debug("msg", "idp configured", "idp", i)
		optionTemplate := fmt.Sprintf("<option value=\"%s\">Employee: (%s)</option>\n", strings.TrimSpace(i), strings.TrimSpace(i))
		optionsBuilder.WriteString(optionTemplate)
	}

	// Replace the placeholder in the HTML template with the generated options
	finalHTML := strings.Replace(htmlTemplate, "{{IDP_OPTIONS}}", optionsBuilder.String(), -1)

	// Set the content type and write the final HTML to the response
	rw.Header().Set("Content-Type", "text/html")
	fmt.Fprint(rw, finalHTML)

	return nil
}

func handleIDPSelection(api orchestrator.Orchestrator, rw http.ResponseWriter, req *http.Request) error {
	log := api.Logger()
	session, _ := api.Session()
	log.Info("msg", "parsing form from request")

	// Parse the form from the request
	err := req.ParseForm()
	if err != nil {
		return fmt.Errorf("failed to parse form from request: %w", err)
	}

	selectedIDP := req.Form.Get("idp")
	log.Info("msg", fmt.Sprintf("authenticating user against '%s'", selectedIDP))

	myIDP, _ := api.IdentityProvider(selectedIDP)

	//once the metadata is unput into the UI - use below to iterate through the list of IDPs to generate a string
	session.SetString("idr.selectedIDP", selectedIDP)
	session.Save()
	referrer := req.Referer()
	if referrer == "" {
		return fmt.Errorf("no referrer found in request")
	}
	referrerURL, err := url.Parse(referrer)
	if err != nil {
		return fmt.Errorf("failed to parse referrer URL: %w", err)
	}

	req.URL.Path = referrerURL.Path

	// Perform the login using the Identity Provider
	myIDP.Login(rw, req)
	return nil

}

// renderWorkRelationForm queries the IDR API by email and populates a drop-down form.
func renderWorkRelationForm(idpName string, rw http.ResponseWriter, api orchestrator.Orchestrator) error {
	log := api.Logger()
	log.Debug("msg", "retrieving user email from session to query IDR API")

	session, _ := api.Session()
	email, _ := session.GetString(idpName + ".email")
	log.Debug("msg", idpName+".email"+"value is: "+email)
	if len(email) == 0 {
		email, _ := session.GetString(idpName + ".preferred_username")
		log.Debug("msg", idpName+".preferred_username"+"value is: "+email)
		if len(email) == 0 {
			log.Debug("msg", "user email not found on session")
			return errors.New("user email not found on session")
		}
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		log.Debug("msg", "x509 not found")
		return fmt.Errorf("failed to create system cert pool: %w", err)
	}

	ca, err := os.ReadFile(idrRootCAPath)
	if err != nil {
		log.Debug("msg", "idrRootCAPATH issue")
		return fmt.Errorf("failed to read root CA cert: %w", err)
	}
	ok := certPool.AppendCertsFromPEM(ca)
	if !ok {
		log.Debug("msg", "append Certs not issued")
		return fmt.Errorf("failed to append CA cert to cert pool")
	}
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf(idrUserEndpoint, email))
	if err != nil {
		return fmt.Errorf("unable to GET user email: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user is not found in IDR")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received unexpected status code from IDR API: %d", resp.StatusCode)
	}
	log.Debug("msg", "received response from IDR API")

	var user User
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		return fmt.Errorf("unable to decode json response body: %s", err)
	}

	log.Debug(
		"msg", "storing user returned from IDR API on session",
		"userID", user.Id,
		"userEmail", user.Email,
	)
	userBytes, err := json.Marshal(user)
	if err != nil {
		log.Debug("msg", "not marshalled correctly")
		return fmt.Errorf("failed to serialize user: %s", err)
	}
	session.SetBytes("idr.user", userBytes)
	session.Save()
	t, err := template.ParseFiles(workrelationFormTemplatePath)
	if err != nil {
		return fmt.Errorf("unable to parse template form: %s", err)
	}
	//create a session.set()
	err = t.Execute(rw, user)
	if err != nil {
		log.Debug("msg", "unable to execute template")
		return fmt.Errorf("unable to execute template: %s", err)
	}

	return nil
}

func handleWorkRelationSelection(req *http.Request, rw http.ResponseWriter, api orchestrator.Orchestrator) error {
	log := api.Logger()
	log.Debug("msg", "handling work relations form submission")
	err := req.ParseForm()
	if err != nil {
		return fmt.Errorf("unable to parse work relations form submission: %s", err)
	}

	workRelationID := req.Form.Get("wr")
	if len(workRelationID) == 0 {
		return fmt.Errorf("unable to parse out workrelation id")
	}
	log.Debug(
		"msg", " selected work relation",
		"workRelationID", workRelationID,
	)

	session, _ := api.Session()
	userBytes, ok := session.GetBytes("idr.user")
	if ok != nil {
		return fmt.Errorf("unable to decode idr.user")
	}
	var userStruct User

	json.Unmarshal(userBytes, &userStruct)
	for _, wr := range userStruct.Workrelations {
		log.Debug("msg work relation ID", wr.WrId)
		if wr.WrId == workRelationID {
			roles := strings.Join(wr.Roles, ",")
			log.Debug(
				"msg", "storing work relation roles on session",
				"roles", roles,
			)
			session.SetString("idr.roles", roles)
			session.Save()
		}
	}

	log.Debug(
		"msg", "redirecting user to originally selected resource",
		"location", req.Referer(),
	)
	http.Redirect(rw, req, req.Referer(), http.StatusFound)
	return nil
}
