package sid

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/sedind/sid/drivers"
	"github.com/sedind/sid/models"
	"golang.org/x/oauth2"
	"gopkg.in/oleiade/reflections.v1"
)

// Dispatcher - responsible for issuing concurent identities
type Dispatcher struct {
	identities map[string]*Identity
	sync.RWMutex
}

//NewDispatcher creates Dispatcher instance
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		identities: make(map[string]*Identity),
	}
}

// New creates new Identity instance
func New(d *Dispatcher) *Identity {
	d.Lock()
	defer d.Unlock()
	state := randToken()
	i := &Identity{
		state: state,
	}
	d.identities[state] = i
	return i
}

// Handle - Callback method that can be called only once for given state
func (d *Dispatcher) Handle(state string, code string) (*models.User, *oauth2.Token, error) {
	d.RLock()
	identity, ok := d.identities[state]
	d.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("invalid SCRF token: %s", state)
	}

	err := identity.Handle(state, code)
	d.Lock()
	delete(d.identities, state)
	d.Unlock()
	return &identity.User, identity.Token, err
}

// Identity data type
type Identity struct {
	driver string
	state  string
	scopes []string
	cfg    *oauth2.Config
	User   models.User
	Token  *oauth2.Token
}

func init() {
	drivers.InitializeDrivers(RegisterNewDriver)
}

var (
	//Set the basic information such as the endpoint and the scopes URIs
	apiMap = map[string]map[string]string{}

	//Mapping to create valid user struct from providers
	userMap = map[string]map[string]string{}

	//Map correct endpoints
	endpointMap = map[string]oauth2.Endpoint{}

	//Map custom callbacks
	callbackMap = map[string]func(client *http.Client, u *models.User){}
	//Default scopes for each driver
	defaultScopesMap = map[string][]string{}
)

// RegisterNewDriver adds a new driver
func RegisterNewDriver(driver string, defaultscopes []string, callback func(client *http.Client, u *models.User), endpoint oauth2.Endpoint, apimap, usermap map[string]string) {
	apiMap[driver] = apimap
	userMap[driver] = usermap
	endpointMap[driver] = endpoint
	callbackMap[driver] = callback
	defaultScopesMap[driver] = defaultscopes
}

// Driver gets identity object for a given driver
func (i *Identity) Driver(driver string) *Identity {
	i.driver = driver
	i.scopes = defaultScopesMap[driver]

	if i.state == "" {
		i.state = randToken()
	}

	return i
}

// Scopes Appends Identity oAuth scopes
func (i *Identity) Scopes(scopes []string) *Identity {
	i.scopes = append(i.scopes, scopes...)
	return i
}

// Redirect returns an URL for the selected oAuth login
func (i *Identity) Redirect(clientID, clientSecret, redirectURL string) (string, error) {
	// check if driver is valid
	if !isDriverValid(i.driver) {
		return "", fmt.Errorf("Driver not valid: %s", i.driver)
	}
	// check if redirectURL is valid
	_, err := url.ParseRequestURI(redirectURL)
	if err != nil {
		return "", fmt.Errorf("REdirect URL <%s> not valid: %s", redirectURL, err.Error())
	}
	// check if redirectURL has valid scheme
	if !strings.HasPrefix(redirectURL, "https://") && !strings.HasPrefix(redirectURL, "http://") {
		return "", fmt.Errorf("Redirect URL <%s> not valid: protocol not valid", redirectURL)
	}

	i.cfg = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       i.scopes,
		Endpoint:     endpointMap[i.driver],
	}
	return i.cfg.AuthCodeURL(i.state), nil
}

// Handle callback from provider
func (i *Identity) Handle(state, code string) error {
	// Handle the exchange code to initiate a transport
	if i.state != state {
		return fmt.Errorf("Invalid state : %s", state)
	}

	//check if driver is valid
	if !isDriverValid(i.driver) {
		return fmt.Errorf("Driver not valid: %s", i.driver)
	}
	token, err := i.cfg.Exchange(oauth2.NoContext, code)
	if err != nil {
		return fmt.Errorf("oAuth exchange failed: %s", err.Error())
	}

	client := i.cfg.Client(oauth2.NoContext, token)
	// get social token
	i.Token = token
	driverAPIMap := apiMap[i.driver]
	driverUserMap := userMap[i.driver]
	userEndpoint := strings.Replace(driverAPIMap["userEndpoint"], "%ACCESS_TOKEN%", token.AccessToken, -1)

	//get user info
	req, err := client.Get(driverAPIMap["endpoint"] + userEndpoint)
	if err != nil {
		return err
	}

	defer req.Body.Close()

	res, _ := ioutil.ReadAll(req.Body)
	data, err := jsonDecode(res)
	if err != nil {
		return fmt.Errorf("Error decoding JSON: %s", err.Error())
	}

	mapKeys := keys(driverUserMap)
	usr := models.User{}
	for k, v := range data {
		if !inSlice(k, mapKeys) { // Skip if not in the mapping
			continue
		}
		_ = reflections.SetField(&usr, driverUserMap[k], fmt.Sprint(v))
	}

	// set the "raw" user interface
	usr.Raw = data

	//custom callback
	callbackMap[i.driver](client, &usr)
	i.User = usr

	return nil

}

////////////////////////////////////////////////////////////////////////////////
// Utility Methods
////////////////////////////////////////////////////////////////////////////////

// Decode a json or return an error
func jsonDecode(js []byte) (map[string]interface{}, error) {
	var decoded map[string]interface{}
	if err := json.Unmarshal(js, &decoded); err != nil {
		return nil, err
	}

	return decoded, nil
}

func isDriverValid(driver string) bool {
	return inSlice(driver, complexKeys(apiMap))
}

// keys returns array of keys from map
func keys(m map[string]string) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// complexKeys returns array of keys from complex map object
func complexKeys(m map[string]map[string]string) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// inSlice checks if a value is in a string slice
func inSlice(v string, s []string) bool {
	for _, scope := range s {
		if scope == v {
			return true
		}
	}
	return false
}

// randToken generates random 32 character string
func randToken() string {
	ba := make([]byte, 32)
	rand.Read(ba)
	return base64.StdEncoding.EncodeToString(ba)

}
