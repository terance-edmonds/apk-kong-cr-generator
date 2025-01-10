/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package generators

import (
	"apk_kong_lib/config/constants"
	"apk_kong_lib/config/types"
	"apk_kong_lib/pkg/utils"
)

// GenerateRateLimitPlugin generates a Kong rate limit plugin based on the rate limit configuration.
func GenerateRateLimitPlugin(rateLimit types.RateLimit, targetRefName string, operation *types.Operation) types.KongRateLimitPlugin {
	config := types.KongRateLimitPluginConfig{}
	if rateLimit.Unit == "Second" {
		config.Second = rateLimit.RequestsPerUnit
	} else if rateLimit.Unit == "Minute" {
		config.Minute = rateLimit.RequestsPerUnit
	} else if rateLimit.Unit == "Hour" {
		config.Hour = rateLimit.RequestsPerUnit
	} else if rateLimit.Unit == "Day" {
		config.Day = rateLimit.RequestsPerUnit
	} else if rateLimit.Unit == "Month" {
		config.Month = rateLimit.RequestsPerUnit
	} else if rateLimit.Unit == "Year" {
		config.Year = rateLimit.RequestsPerUnit
	}

	kongRateLimitPlugin := types.KongRateLimitPlugin{
		APIVersion: "configuration.konghq.com/v1",
		Kind:       "KongPlugin",
		Plugin:     "rate-limiting",
		Enabled:    true,
		Metadata: types.Metadata{
			Name: utils.GeneratePluginRefName(operation, targetRefName, "rate_limiting"),
		},
		Config: config,
	}
	return kongRateLimitPlugin
}

// GenerateCorsPlugin generates a Kong CORS plugin based on the CORS configuration.
func GenerateCorsPlugin(corsConfiguration types.CORSConfiguration, targetRefName string) types.KongCorsPlugin {
	return types.KongCorsPlugin{
		APIVersion: "configuration.konghq.com/v1",
		Kind:       "KongPlugin",
		Plugin:     "cors",
		Enabled:    corsConfiguration.CORSConfigurationEnabled,
		Metadata: types.Metadata{
			Name: utils.GeneratePluginRefName(nil, targetRefName, "cors"),
		},
		Config: types.KongCorsPluginConfig{
			Origins:     utils.CheckValue(corsConfiguration.AccessControlAllowOrigins, make([]string, 0)).([]string),
			Headers:     corsConfiguration.AccessControlAllowHeaders,
			Methods:     utils.CheckValue(corsConfiguration.AccessControlAllowMethods, constants.HTTP_DEFAULT_METHODS).([]string),
			MaxAge:      0,
			Credentials: utils.CheckValue(corsConfiguration.AccessControlAllowCredentials, false).(bool),
		},
	}
}

// GenerateAuthenticationPlugin generates authentication plugins based on the authentication requests.
func GenerateAuthenticationPlugin(authenticationRequests *[]types.AuthConfiguration, targetRefName string, operation *types.Operation) []interface{} {
	var authenticationPlugins []interface{}
	if authenticationRequests != nil {
		for _, authenticationRequest := range *authenticationRequests {
			// Generate key auth plugin
			if authenticationRequest.AuthType == "APIKey" {
				authPlugin := generateKeyAuthPlugin(authenticationRequest, targetRefName, operation)
				authenticationPlugins = append(authenticationPlugins, authPlugin)
			}
			// Generate jwt auth plugin
			if authenticationRequest.AuthType == "JWT" {
				authPlugin := generateJWTAuthPlugin(authenticationRequest, targetRefName, operation)
				authenticationPlugins = append(authenticationPlugins, authPlugin)
			}
			// Generate OAuth2 auth plugin
			if authenticationRequest.AuthType == "OAuth2" {
				authPlugin := generateOAuth2AuthPlugin(authenticationRequest, targetRefName, operation)
				authenticationPlugins = append(authenticationPlugins, authPlugin)
			}
			// Generate mTLS auth plugin
			if authenticationRequest.AuthType == "mTLS" {
				authPlugin := generateMTLSAuthPlugin(authenticationRequest, targetRefName, operation)
				authenticationPlugins = append(authenticationPlugins, authPlugin)
			}
		}
	}
	return authenticationPlugins
}

// generateKeyAuthPlugin generates a Kong key auth plugin based on the auth configuration.
func generateKeyAuthPlugin(authConfiguration types.AuthConfiguration, targetRefName string, operation *types.Operation) types.KongKeyAuthPlugin {
	keyAuthPlugin := types.KongKeyAuthPlugin{
		APIVersion: "configuration.konghq.com/v1",
		Kind:       "KongPlugin",
		Plugin:     "key-auth",
		Enabled:    authConfiguration.Enabled,
		Metadata: types.Metadata{
			Name: utils.GeneratePluginRefName(operation, targetRefName, "key_auth"),
		},
		Config: types.KongKeyAuthPluginConfig{
			KeyInBody:       true,
			RunOnPreflight:  true,
			Realm:           "",
			Anonymous:       "",
			HideCredentials: !authConfiguration.SendTokenUpStream,
			KeyNames:        []string{"apiKey"},
			KeyInHeader:     authConfiguration.HeaderEnabled,
			KeyInQuery:      authConfiguration.QueryParamEnable,
		},
	}
	// Add query param name to key names if it's different
	if authConfiguration.HeaderName != "apiKey" {
		keyAuthPlugin.Config.KeyNames = append(keyAuthPlugin.Config.KeyNames, authConfiguration.HeaderName)
	}
	// Add query param name to key names if it's different
	if authConfiguration.HeaderName != authConfiguration.QueryParamName {
		keyAuthPlugin.Config.KeyNames = append(keyAuthPlugin.Config.KeyNames, authConfiguration.QueryParamName)
	}
	return keyAuthPlugin
}

// generateJWTAuthPlugin generates a Kong JWT auth plugin based on the auth configuration.
func generateJWTAuthPlugin(authConfiguration types.AuthConfiguration, targetRefName string, operation *types.Operation) types.KongJWTAuthPlugin {
	jwtAuthPlugin := types.KongJWTAuthPlugin{
		APIVersion: "configuration.konghq.com/v1",
		Kind:       "KongPlugin",
		Plugin:     "jwt",
		Enabled:    authConfiguration.Enabled,
		Metadata: types.Metadata{
			Name: utils.GeneratePluginRefName(operation, targetRefName, "jwt"),
		},
		Config: types.KongJWTAuthPluginConfig{
			KeyClaimName:   "iss",
			RunOnPreflight: true,
			SecretIsBase64: false,
			HeaderNames:    []string{"Authorization"},
			UriParamNames:  []string{"jwt"},
		},
	}
	if authConfiguration.HeaderName != "" {
		jwtAuthPlugin.Config.HeaderNames = []string{authConfiguration.HeaderName}
	}
	return jwtAuthPlugin
}

// generateOAuth2AuthPlugin generates a Kong OAuth2 auth plugin based on the auth configuration.
func generateOAuth2AuthPlugin(authConfiguration types.AuthConfiguration, targetRefName string, operation *types.Operation) types.KongOAuth2AuthPlugin {
	pluginName := utils.GeneratePluginRefName(operation, targetRefName, "oauth2")
	oauth2AuthPlugin := types.KongOAuth2AuthPlugin{
		APIVersion: "configuration.konghq.com/v1",
		Kind:       "KongPlugin",
		Plugin:     "oauth2",
		Enabled:    authConfiguration.Enabled,
		Metadata: types.Metadata{
			Name: pluginName,
		},
		Config: types.KongOAuth2AuthPluginConfig{
			TokenExpiration:               7200,
			MandatoryScope:                false,
			EnableAuthorizationCode:       false,
			EnableImplicitGrant:           false,
			EnableClientCredentials:       false,
			EnablePasswordGrant:           false,
			AcceptHttpIfAlreadyTerminated: false,
			GlobalCredentials:             false,
			AuthHeaderName:                "Authorization",
			RefreshTokenTTL:               1209600,
			ReuseRefreshToken:             false,
			PersistentRefreshToken:        false,
			Pkce:                          "lax",
			Scopes:                        []string{},
			Realm:                         "",
			Anonymous:                     "",
			HideCredentials:               !authConfiguration.SendTokenUpStream,
			ProvisionKey:                  utils.GenerateProvisionKey(pluginName),
		},
	}
	if authConfiguration.HeaderName != "" {
		oauth2AuthPlugin.Config.AuthHeaderName = authConfiguration.HeaderName
	}
	return oauth2AuthPlugin
}

// generateMTLSAuthPlugin generates a Kong mTLS auth plugin based on the auth configuration.
func generateMTLSAuthPlugin(authConfiguration types.AuthConfiguration, targetRefName string, operation *types.Operation) types.KongMTLSAuthPlugin {
	var cACertificates []string
	for _, certificate := range authConfiguration.Certificates {
		cACertificates = append(cACertificates, certificate.Key)
	}
	mTLSAuthPlugin := types.KongMTLSAuthPlugin{
		APIVersion: "configuration.konghq.com/v1",
		Kind:       "KongPlugin",
		Plugin:     "mtls-auth",
		Enabled:    authConfiguration.Enabled,
		Metadata: types.Metadata{
			Name: utils.GeneratePluginRefName(operation, targetRefName, "mtls_auth"),
		},
		Config: types.KongMTLSAuthPluginConfig{
			ConsumerBy:           "username",
			CacheTTL:             60,
			SkipConsumerLookup:   false,
			AllowPartialChain:    false,
			AuthenticatedGroupBy: "CN",
			RevocationCheckMode:  "IGNORE_CA_ERROR",
			HTTPTimeout:          30000,
			CertCacheTTL:         60000,
			SendCADN:             false,
			DefaultConsumer:      "",
			HTTPProxyHost:        "",
			HTTPProxyPort:        0,
			HTTPSProxyHost:       "",
			HTTPSProxyPort:       0,
			Anonymous:            "",
			CACertificates:       cACertificates,
		},
	}
	return mTLSAuthPlugin
}
