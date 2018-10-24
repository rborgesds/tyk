package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"github.com/pmylund/go-cache"

	"github.com/TykTechnologies/openid2go/openid"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

const OIDPREFIX = "openid"

var openIDScopeCache = cache.New(240*time.Second, 30*time.Second)

type OpenIDMW struct {
	BaseMiddleware
	providerConfiguration     *openid.Configuration
	provider_client_policymap map[string]map[string]string
	lock                      sync.RWMutex
	providerConfigs           map[string]apidef.OIDProviderConfig
	httpClient                *http.Client
}

func (k *OpenIDMW) Name() string {
	return "OpenIDMW"
}

func (k *OpenIDMW) EnabledForSpec() bool {
	return k.Spec.UseOpenID
}

func (k *OpenIDMW) Init() {
	k.provider_client_policymap = make(map[string]map[string]string)
	// Create an OpenID Configuration and store
	var err error
	k.providerConfiguration, err = openid.NewConfiguration(openid.ProvidersGetter(k.getProviders),
		openid.ErrorHandler(k.dummyErrorHandler))
	if err != nil {
		k.Logger().WithError(err).Error("OpenID configuration error")
	}

	// prepare map issuer->config to lookup configs when processing requests
	k.providerConfigs = make(map[string]apidef.OIDProviderConfig)
	for _, providerConf := range k.Spec.OpenIDOptions.Providers {
		k.providerConfigs[providerConf.Issuer] = providerConf
	}

	k.httpClient = &http.Client{} // client to call token introspection endpoints
}

func (k *OpenIDMW) getProviders() ([]openid.Provider, error) {
	providers := []openid.Provider{}
	k.Logger().Debug("Setting up providers: ", k.Spec.OpenIDOptions.Providers)
	for _, provider := range k.Spec.OpenIDOptions.Providers {
		iss := provider.Issuer
		k.Logger().Debug("Setting up Issuer: ", iss)
		providerClientArray := make([]string, len(provider.ClientIDs))

		i := 0
		for clientID, policyID := range provider.ClientIDs {
			clID, _ := base64.StdEncoding.DecodeString(clientID)
			clientID := string(clID)

			k.lock.Lock()
			if k.provider_client_policymap[iss] == nil {
				k.provider_client_policymap[iss] = map[string]string{clientID: policyID}
			} else {
				k.provider_client_policymap[iss][clientID] = policyID
			}
			k.lock.Unlock()

			k.Logger().Debug("--> Setting up client: ", clientID, " with policy: ", policyID)
			providerClientArray[i] = clientID
			i++
		}

		p, err := openid.NewProvider(iss, providerClientArray)

		if err != nil {
			k.Logger().WithError(err).WithFields(logrus.Fields{
				"provider": iss,
			}).Error("Failed to create provider")
		} else {
			providers = append(providers, p)
		}
	}

	return providers, nil
}

// We don't want any of the error handling, we use our own
func (k *OpenIDMW) dummyErrorHandler(e error, w http.ResponseWriter, r *http.Request) bool {
	k.Logger().WithError(e).Warning("JWT Invalid")
	return true
}

func (k *OpenIDMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	logger := k.Logger()
	// 1. Validate the JWT
	ouser, token, halt := openid.AuthenticateOIDWithUser(k.providerConfiguration, w, r)

	// 2. Generate the internal representation for the key
	if halt {
		// Fire Authfailed Event
		k.reportLoginFailure("[JWT]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	// 3. Create or set the session to match
	iss, found := token.Claims.(jwt.MapClaims)["iss"]
	clients, cfound := token.Claims.(jwt.MapClaims)["aud"]

	if !found && !cfound {
		logger.Error("No issuer or audiences found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	providerConf, ok := k.providerConfigs[iss.(string)]
	if !ok {
		logger.Error("No issuer or audiences found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	// decide if we use policy ID from provider client settings or list of policies from scope-policy mapping
	useScope := providerConf.IntrospectionEndpoint != ""

	k.lock.RLock()
	clientSet, foundIssuer := k.provider_client_policymap[iss.(string)]
	k.lock.RUnlock()
	if !foundIssuer {
		logger.Error("No issuer or audiences found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	policyID := ""
	clientID := ""
	clientIDVal := ""

	switch v := clients.(type) {
	case string:
		k.lock.RLock()
		clientIDVal = clientSet[v]
		k.lock.RUnlock()
		clientID = v
	case []interface{}:
		for _, audVal := range v {
			k.lock.RLock()
			val, found := clientSet[audVal.(string)]
			k.lock.RUnlock()
			if found {
				clientID = audVal.(string)
				clientIDVal = val
				break
			}
		}
	}

	data := []byte(ouser.ID)
	keyID := fmt.Sprintf("%x", md5.Sum(data))
	sessionID := generateToken(k.Spec.OrgID, keyID)

	if k.Spec.OpenIDOptions.SegregateByClient {
		// We are segregating by client, so use it as part of the internal token
		logger.Debug("Client ID:", clientID)
		sessionID = generateToken(k.Spec.OrgID, fmt.Sprintf("%x", md5.Sum([]byte(clientID)))+keyID)
	}

	logger.Debug("Generated Session ID: ", sessionID)

	var policiesToApply []string
	if !useScope {
		// use policy ID specified for this client
		policyID = clientIDVal
		if policyID == "" {
			logger.Error("No matching policy found!")
			k.reportLoginFailure("[NOT GENERATED]", r)
			return errors.New("Key not authorised"), http.StatusUnauthorized
		}
	} else {
		// get scope for that token ID and prepare list of policies from scope
		policiesToApply = k.getPoliciesFromScope(providerConf, clientID, sessionID, token.Raw)
		if policiesToApply == nil {
			logger.Error("No policies found from scope!")
			k.reportLoginFailure("[NOT GENERATED]", r)
			return errors.New("Key not authorised"), http.StatusUnauthorized
		}
	}

	session, exists := k.CheckSessionAndIdentityForValidKey(sessionID, r)
	if !exists {
		// Create it
		logger.Debug("Key does not exist, creating")
		session = user.SessionState{}

		if !useScope {
			// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
			newSession, err := generateSessionFromPolicy(policyID,
				k.Spec.OrgID,
				true)

			if err != nil {
				k.reportLoginFailure(sessionID, r)
				logger.Error("Could not find a valid policy to apply to this token!")
				return errors.New("Key not authorized: no matching policy"), http.StatusForbidden
			}

			session = newSession
		}

		session.OrgID = k.Spec.OrgID
		session.MetaData = map[string]interface{}{"TykJWTSessionID": sessionID, "ClientID": clientID}
		session.Alias = clientID + ":" + ouser.ID

		// Update the session in the session manager in case it gets called again
		logger.Debug("Policy applied to key")
	}

	if !useScope {
		// policy was set per client
		session.SetPolicies(policyID)
	} else {
		// session will have several policies assigned via scope
		session.SetPolicies(policiesToApply...)
	}

	if err := k.ApplyPolicies(sessionID, &session); err != nil {
		k.Logger().WithError(err).Error("Could not apply new policy from OIDC client to session")
		return errors.New("Key not authorized: could not apply new policy"), http.StatusForbidden
	}

	// 4. Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.OIDCUser, apidef.UnsetAuth:
		ctxSetSession(r, &session, sessionID, true)
	}
	ctxSetJWTContextVars(k.Spec, r, token)

	return nil, http.StatusOK
}

func (k *OpenIDMW) getPoliciesFromScope(providerConf apidef.OIDProviderConfig, clientID, sessionID, token string) []string {
	var scopes []string
	if scopeVal, found := openIDScopeCache.Get(sessionID); found {
		// try to get scope from cache first
		scopes = scopeVal.([]string)
	} else {
		// try to get scope via introspection endpoint
		tokenInfo, err := k.getTokenInfo(providerConf.IntrospectionEndpoint, clientID, providerConf.ClientIDs[clientID], token)
		if err != nil {
			k.Logger().WithError(err).Error("Failed to call introspection endpoint")
			return nil
		}
		// check first if token info has "active" field (this field is required by standard but we have it here optional
		// as some OIDPs might not follow standards)
		if active, ok := tokenInfo["active"].(bool); ok {
			if !active {
				k.Logger().Error("this token is not active any more, could not get scope")
				return nil
			}
		}
		// get scope and set it in cache
		if scope, ok := tokenInfo["scope"].(string); !ok {
			k.Logger().Error("field 'scope' was not found in introspection endpoint reply")
			return nil
		} else {
			var exp time.Duration = -1 // no expiration by default
			// check if we have expiration for token
			if expVal, ok := tokenInfo["exp"].(float64); ok {
				expTime := time.Unix(int64(expVal), 0)
				now := time.Now()
				if expTime.Before(now) {
					// already expired
					k.Logger().Error("this token is expired, could not get scope")
					return nil
				}
				exp = expTime.Sub(now)
			}
			scopes = strings.Split(scope, " ")
			// cache scopes with expiration from introspection endpoint reply
			openIDScopeCache.Set(sessionID, scopes, exp)
		}
	}

	// prepare list of policies using mapping scope->policy from provider config
	pols := map[string]bool{}
	for _, scopeItem := range scopes {
		if polID, ok := providerConf.ScopeToPolicyMapping[scopeItem]; ok {
			pols[polID] = true
		}
	}

	if len(pols) == 0 {
		return nil
	}

	policies := make([]string, 0, len(pols))
	for polID := range pols {
		policies = append(policies, polID)
	}

	return policies
}

func (k *OpenIDMW) getTokenInfo(introspectionEndpoint string, clientID string, clientSecret string, token string) (map[string]interface{}, error) {
	payload := url.Values{}

	// OIDPs are supposed to follow https://tools.ietf.org/html/rfc7662 but they don't so here we have some code specific to different providers

	switch {
	case strings.Contains(introspectionEndpoint, "google"):
		// set google-specific fields per https://developers.google.com/identity/sign-in/web/backend-auth#calling-the-tokeninfo-endpoint
		payload.Add("id_token", token)
	case strings.Contains(introspectionEndpoint, "okta"):
		// set okta-specific fields per https://developer.okta.com/docs/api/resources/oidc#introspec
		payload.Add("token", token)
		payload.Add("token_type_hint", "id_token")
		payload.Add("client_id", clientID)
		if clientSecret != "" {
			payload.Add("client_secret", clientSecret)
		}
	default:
		payload.Add("token", token) // that's the only required field by rfc7662
	}

	resp, err := k.httpClient.PostForm(introspectionEndpoint, payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got bad status code '%s' from introspection endpoint", resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	tokenInfo := map[string]interface{}{}
	if err := json.Unmarshal(data, &tokenInfo); err != nil {
		return nil, err
	}

	return tokenInfo, nil
}

func (k *OpenIDMW) reportLoginFailure(tykId string, r *http.Request) {
	k.Logger().WithFields(logrus.Fields{
		"key": obfuscateKey(tykId),
	}).Warning("Attempted access with invalid key.")

	// Fire Authfailed Event
	AuthFailed(k, r, tykId)

	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "1")
}
