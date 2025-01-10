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

package types

// RateLimit represents the rate limit configuration.
type Metadata struct {
	Name              string               `yaml:"name"`
	Namespace         string               `yaml:"namespace,omitempty"`
	UID               string               `yaml:"uid,omitempty"`
	CreationTimestamp string               `yaml:"creationTimestamp,omitempty"`
	SelfLink          string               `yaml:"selfLink,omitempty"`
	ResourceVersion   string               `yaml:"resourceVersion,omitempty"`
	OwnerReferences   []OwnerReference     `yaml:"ownerReferences,omitempty"`
	ManagedFields     []ManagedFieldsEntry `yaml:"managedFields,omitempty"`
	Generation        int                  `yaml:"generation,omitempty"`
	GenerateName      string               `yaml:"generateName,omitempty"`
	Labels            map[string]string    `yaml:"labels,omitempty"`
	Annotations       map[string]string    `yaml:"annotations,omitempty"`
}

// OwnerReference represents an owner reference.
type OwnerReference struct {
	APIVersion         string `yaml:"apiVersion"`
	BlockOwnerDeletion bool   `yaml:"blockOwnerDeletion,omitempty"` // false
	Controller         bool   `yaml:"controller,omitempty"`         // false
	Kind               string `yaml:"kind"`
	Name               string `yaml:"name"`
	UID                string `yaml:"uid"`
}

// ManagedFieldsEntry represents a managed fields entry.
type ManagedFieldsEntry interface{}

// KongRateLimitPluginConfig represents the configuration for the Kong rate limit plugin.
type KongRateLimitPluginConfig struct {
	Second int    `yaml:"second,omitempty"`
	Minute int    `yaml:"minute,omitempty"`
	Hour   int    `yaml:"hour,omitempty"`
	Day    int    `yaml:"day,omitempty"`
	Month  int    `yaml:"month,omitempty"`
	Year   int    `yaml:"year,omitempty"`
	Policy string `yaml:"policy,omitempty"`
}

// KongRateLimitPlugin represents the Kong rate limit plugin.
type KongRateLimitPlugin struct {
	APIVersion string                    `yaml:"apiVersion"` // configuration.konghq.com/v1
	Kind       string                    `yaml:"kind"`       // KongPlugin
	Metadata   Metadata                  `yaml:"metadata"`
	Plugin     string                    `yaml:"plugin"`  // rate-limiting
	Enabled    bool                      `yaml:"enabled"` // true
	Config     KongRateLimitPluginConfig `yaml:"config"`
}

// KongKeyAuthPluginConfig represents the configuration for the Kong key auth plugin.
type KongKeyAuthPluginConfig struct {
	KeyNames        []string `yaml:"key_names"`
	HideCredentials bool     `yaml:"hide_credentials,omitempty"` // false
	KeyInHeader     bool     `yaml:"key_in_header,omitempty"`    // true
	KeyInQuery      bool     `yaml:"key_in_query,omitempty"`     // true
	KeyInBody       bool     `yaml:"key_in_body,omitempty"`      // true
	RunOnPreflight  bool     `yaml:"run_on_preflight,omitempty"` // true
	Realm           string   `yaml:"realm,omitempty"`
	Anonymous       string   `yaml:"anonymous,omitempty"`
}

// KongKeyAuthPlugin represents the Kong key auth plugin.
type KongKeyAuthPlugin struct {
	APIVersion string                  `yaml:"apiVersion"` // configuration.konghq.com/v1
	Kind       string                  `yaml:"kind"`       // KongPlugin
	Metadata   Metadata                `yaml:"metadata"`
	Plugin     string                  `yaml:"plugin"`  // key-auth
	Enabled    bool                    `yaml:"enabled"` // true
	Config     KongKeyAuthPluginConfig `yaml:"config"`
}

// KongJWTAuthPluginConfig represents the configuration for the Kong jwt auth plugin.
type KongJWTAuthPluginConfig struct {
	KeyClaimName      string   `yaml:"key_claim_name"`   // "iss"
	RunOnPreflight    bool     `yaml:"run_on_preflight"` // true
	SecretIsBase64    bool     `yaml:"secret_is_base64"` // false
	MaximumExpiration int      `yaml:"maximum_expiration"`
	HeaderNames       []string `yaml:"header_names"`    // ["Authorization"]
	UriParamNames     []string `yaml:"uri_param_names"` // ["jwt"]
	CookieNames       []string `yaml:"cookie_names,omitempty"`
	ClaimsToVerify    string   `yaml:"claims_to_verify,omitempty"`
	Realm             string   `yaml:"realm,omitempty"`
	Anonymous         string   `yaml:"anonymous,omitempty"`
}

// KongJWTAuthPlugin represents the Kong jwt auth plugin.
type KongJWTAuthPlugin struct {
	APIVersion string                  `yaml:"apiVersion"` // configuration.konghq.com/v1
	Kind       string                  `yaml:"kind"`       // KongPlugin
	Metadata   Metadata                `yaml:"metadata"`
	Plugin     string                  `yaml:"plugin"`  // jwt
	Enabled    bool                    `yaml:"enabled"` // true
	Config     KongJWTAuthPluginConfig `yaml:"config"`
}

// KongOAuth2AuthPluginConfig represents the configuration for the Kong oauth2 auth plugin.
type KongOAuth2AuthPluginConfig struct {
	ProvisionKey                  string   `yaml:"provision_key"`
	TokenExpiration               int      `yaml:"token_expiration,omitempty"`                  // 7200
	MandatoryScope                bool     `yaml:"mandatory_scope,omitempty"`                   // false
	EnableAuthorizationCode       bool     `yaml:"enable_authorization_code,omitempty"`         // false
	EnableImplicitGrant           bool     `yaml:"enable_implicit_grant,omitempty"`             // false
	EnableClientCredentials       bool     `yaml:"enable_client_credentials,omitempty"`         // false
	EnablePasswordGrant           bool     `yaml:"enable_password_grant,omitempty"`             // false
	HideCredentials               bool     `yaml:"hide_credentials,omitempty"`                  // false
	AcceptHttpIfAlreadyTerminated bool     `yaml:"accept_http_if_already_terminated,omitempty"` // false
	GlobalCredentials             bool     `yaml:"global_credentials,omitempty"`                // false
	AuthHeaderName                string   `yaml:"auth_header_name,omitempty"`                  // "Authorization"
	RefreshTokenTTL               int      `yaml:"refresh_token_ttl,omitempty"`                 // 1209600
	ReuseRefreshToken             bool     `yaml:"reuse_refresh_token,omitempty"`               // false
	PersistentRefreshToken        bool     `yaml:"persistent_refresh_token,omitempty"`          // false
	Pkce                          string   `yaml:"pkce,omitempty"`                              // "lax"
	Scopes                        []string `yaml:"scopes,omitempty"`
	Realm                         string   `yaml:"realm,omitempty"`
	Anonymous                     string   `yaml:"anonymous,omitempty"`
}

// KongOAuth2AuthPlugin represents the Kong oauth2 auth plugin.
type KongOAuth2AuthPlugin struct {
	APIVersion string                     `yaml:"apiVersion"` // configuration.konghq.com/v1
	Kind       string                     `yaml:"kind"`       // KongPlugin
	Metadata   Metadata                   `yaml:"metadata"`
	Plugin     string                     `yaml:"plugin"`  // oauth2
	Enabled    bool                       `yaml:"enabled"` // true
	Config     KongOAuth2AuthPluginConfig `yaml:"config"`
}

// KongMTLSAuthPluginConfig represents the configuration for the Kong mTLS auth plugin.
type KongMTLSAuthPluginConfig struct {
	CACertificates       []string `yaml:"ca_certificates,omitempty"`
	ConsumerBy           string   `yaml:"consumer_by,omitempty"`            // "username, custom_id"
	CacheTTL             int      `yaml:"cache_ttl,omitempty"`              // 60
	SkipConsumerLookup   bool     `yaml:"skip_consumer_lookup,omitempty"`   // false
	AllowPartialChain    bool     `yaml:"allow_partial_chain,omitempty"`    // false
	AuthenticatedGroupBy string   `yaml:"authenticated_group_by,omitempty"` // "CN"
	RevocationCheckMode  string   `yaml:"revocation_check_mode,omitempty"`  // "IGNORE_CA_ERROR"
	HTTPTimeout          int      `yaml:"http_timeout,omitempty"`           // 30000
	CertCacheTTL         int      `yaml:"cert_cache_ttl,omitempty"`         // 60000
	SendCADN             bool     `yaml:"send_ca_dn,omitempty"`             // false
	DefaultConsumer      string   `yaml:"default_consumer,omitempty"`
	HTTPProxyHost        string   `yaml:"http_proxy_host,omitempty"`
	HTTPProxyPort        int      `yaml:"http_proxy_port,omitempty"`
	HTTPSProxyHost       string   `yaml:"https_proxy_host,omitempty"`
	HTTPSProxyPort       int      `yaml:"https_proxy_port,omitempty"`
	Anonymous            string   `yaml:"anonymous,omitempty"`
}

// KongMTLSAuthPlugin represents the Kong mTLS auth plugin.
type KongMTLSAuthPlugin struct {
	APIVersion string                   `yaml:"apiVersion"` // configuration.konghq.com/v1
	Kind       string                   `yaml:"kind"`       // KongPlugin
	Metadata   Metadata                 `yaml:"metadata"`
	Plugin     string                   `yaml:"plugin"`  // mtls-auth
	Enabled    bool                     `yaml:"enabled"` // true
	Config     KongMTLSAuthPluginConfig `yaml:"config"`
}

// All possible kong authentication types that supports APK
type KongAuthenticationPlugin interface {
	KongKeyAuthPlugin | KongJWTAuthPlugin | KongOAuth2AuthPlugin | KongMTLSAuthPlugin
}

// KongCorsPluginConfig represents the configuration for the Kong CORS plugin.
type KongCorsPluginConfig struct {
	Origins           []string `yaml:"origins,omitempty"`
	Methods           []string `yaml:"methods,omitempty"` // ["get", "put", "post", "delete", "patch"]
	MaxAge            int      `yaml:"max_age,omitempty"`
	Credentials       bool     `yaml:"credentials,omitempty"`        // false
	PrivateNetwork    bool     `yaml:"private_network,omitempty"`    // false
	PreflightContinue bool     `yaml:"preflight_continue,omitempty"` // false
	Headers           []string `yaml:"headers,omitempty"`
	ExposedHeaders    []string `yaml:"exposed_headers,omitempty"`
}

// KongCorsPlugin represents the Kong CORS plugin.
type KongCorsPlugin struct {
	APIVersion string               `yaml:"apiVersion"` // configuration.konghq.com/v1
	Kind       string               `yaml:"kind"`       // KongPlugin
	Metadata   Metadata             `yaml:"metadata"`
	Plugin     string               `yaml:"plugin"`  // cors
	Enabled    bool                 `yaml:"enabled"` // true
	Config     KongCorsPluginConfig `yaml:"config"`
}
