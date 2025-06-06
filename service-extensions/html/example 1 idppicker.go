package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/strata-io/service-extension/orchestrator"
)

const (
	// oldcoIDP represents the name of the IDP that oldco users authenticate against.
	oldcoIDP = "oldco-Okta"
	// newcoIDP represents the name of the IDP that newco users authenticate
	// against.
	newcoIDP = "newco-Entra"
	// newcoUserSuffix is used to distinguish newco users from oldco users.
	newcoUserSuffix = "@domain.com"
)

// IsAuthenticated determines if the user is authenticated. Authentication status is
// derived by querying the session cache.
func IsAuthenticated(
	api orchestrator.Orchestrator,
	_ http.ResponseWriter,
	_ *http.Request,
) bool {
	return checkIsAuthenticated(api)
}

func checkIsAuthenticated(api orchestrator.Orchestrator) bool {
	logger := api.Logger()
	sess, _ := api.Session()

	logger.Debug("msg", "determining if user is authenticated")

	oldcoAuthenticated, _ := sess.GetString(fmt.Sprintf("%s.authenticated", oldcoIDP))
	if oldcoAuthenticated == "true" {
		logger.Debug("msg", "user is authenticated by okta-sonarsystems-com")
		mapClaim(api, oldcoIDP+".email", "generic.SM_USER")
		mapClaim(api, oldcoIDP+".firstName", "generic.firstname")
		mapClaim(api, oldcoIDP+".lastName", "generic.lastname")
		mapClaim(api, oldcoIDP+".name", "generic.email")

		return true
	}

	newcoAuthenticated, _ := sess.GetString(fmt.Sprintf("%s.authenticated", newcoIDP))
	if newcoAuthenticated == "true" {
		logger.Debug("msg", "user is authenticated by azure-sonarsystems-saml")
		mapClaim(api, newcoIDP+".email", "generic.SM_USER")
		mapClaim(api, newcoIDP+".givenname", "generic.firstname")
		mapClaim(api, newcoIDP+".surname", "generic.lastname")
		mapClaim(api, newcoIDP+".email", "generic.email")

		return true
	}
	return false
}

func mapClaim(api orchestrator.Orchestrator, oldClaim, newClaim string) {
	logger := api.Logger()
	sess, _ := api.Session()
	claimValue, _ := sess.GetString(oldClaim)
	if claimValue == "" {
		logger.Info(fmt.Sprintf("cannot map claim for %s", oldClaim))
		return
	}
	logger.Info(fmt.Sprintf("mapping new claim %s:%s", newClaim, claimValue))
	_ = sess.SetString(newClaim, claimValue)
	sess.Save()
}

// Authenticate authenticates the user against the IDP that they select.
func Authenticate(
	api orchestrator.Orchestrator,
	rw http.ResponseWriter,
	req *http.Request,
) {
	logger := api.Logger()
	logger.Info("msg", "authenticating user")

	hasIDPBeenPicked := req.FormValue("username")
	if !checkIsAuthenticated(api) && len(hasIDPBeenPicked) == 0 {
		logger.Debug("se", "rendering idp picker")
		_, _ = rw.Write([]byte(fmt.Sprintf(idpForm, req.FormValue("SAMLRequest"))))
		return
	}

	if req.Method != http.MethodPost {
		http.Error(
			rw,
			http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError,
		)
		logger.Error(fmt.Sprintf(
			"receieved unexpected request type '%s', expected POST",
			req.Method,
		))
		return
	}
	logger.Info("msg", "parsing form from request")
	err := req.ParseForm()
	if err != nil {
		http.Error(
			rw,
			http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError,
		)
		logger.Error(fmt.Sprintf(
			"failed to parse form from request: %s",
			err,
		))
		return
	}
	var (
		username     = req.Form.Get("username")
		employeeType = "oldco"
		idp          = oldcoIDP
	)
	if strings.HasSuffix(username, newcoUserSuffix) {
		employeeType = "newco"
		idp = newcoIDP
	}
	logger.Info(
		"msg", fmt.Sprintf("received form submission from '%s'", username),
		"employeeType", employeeType,
	)
	logger.Info("msg", fmt.Sprintf("authenticating user against '%s", idp))
	provider, err := api.IdentityProvider(idp)
	if err != nil {
		http.Error(
			rw,
			http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError,
		)
		logger.Error(fmt.Sprintf("selected IDP '%s' was not found on AuthProvider", idp))
		return
	}
	provider.Login(rw, req)
}

// idpForm is a basic form that is rendered in order to enable the user to pick which
// IDP they want to authenticate against. The markup can be styled as necessary,
// loaded from an external file, be rendered as a dynamic template, etc.
const idpForm = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Capital One Identity Hub </title>
  <style>
  body {
  font-family: Arial, sans-serif;
  background-color: #f2f2f2; /* Replace with your desired background color */
  display: flex;
  justify-content: center;
  <!-- align-items: center; -->
  height: 100vh;
  margin: 0;
}

.login-container {
  background-color: #fff;
  border-radius: 10px;
  box-shadow: 0px 2px 5px rgba(0, 0, 0, 0.1);
  padding: 40px;
  width: 350px;
  text-align: center;
}

.logo {
  max-width: 200px;
  margin-bottom: 30px;
}

input[type="email"] {
  width: 100%;
  padding: 15px;
  margin-bottom: 20px;
  border: 1px solid #ccc;
  border-radius: 5px;
}

button {
  background-color: #007bff; /* Replace with your desired button color */
  color: #fff;
  border: none;
  padding: 15px 25px;
  border-radius: 5px;
  cursor: pointer;
}
  </style>
<body>
  <div class="login-container">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/98/Capital_One_logo.svg/1024px-Capital_One_logo.svg.png?20220620210501"
 alt="Company Logo" class="logo">
    <form method="POST">
    <input type="hidden" name="SAMLRequest" id="SAMLRequest" value="%s">
      <input type="username" name="username" placeholder="User Name" id="username" required>
      <button type="submit">Submit</button>
    </form>
  </div>
</body>
</html>

`
