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
	"testing"

	"apk_kong_lib/config/types"

	"github.com/go-test/deep"
)

func TestGenerateRateLimitPlugin(t *testing.T) {
	rateLimit := types.RateLimit{
		Unit:            "Minute",
		RequestsPerUnit: 100,
	}
	targetRefName := "test-target"

	expected := types.KongRateLimitPlugin{
		APIVersion: "configuration.konghq.com/v1",
		Kind:       "KongPlugin",
		Plugin:     "rate-limiting",
		Enabled:    true,
		Metadata: types.Metadata{
			Name: "service-rate_limiting-test-target",
		},
		Config: types.KongRateLimitPluginConfig{
			Minute: 100,
		},
	}

	result := GenerateRateLimitPlugin(rateLimit, targetRefName, nil)
	if diff := deep.Equal(result, expected); diff != nil {
		t.Errorf("Difference: %v", diff)
	}
}

func TestGenerateCorsPlugin(t *testing.T) {
	corsConfig := types.CORSConfiguration{
		CORSConfigurationEnabled:      true,
		AccessControlAllowOrigins:     []string{"*"},
		AccessControlAllowHeaders:     []string{"Content-Type"},
		AccessControlAllowMethods:     []string{"GET", "POST"},
		AccessControlAllowCredentials: true,
	}
	targetRefName := "test-target"

	expected := types.KongCorsPlugin{
		APIVersion: "configuration.konghq.com/v1",
		Kind:       "KongPlugin",
		Plugin:     "cors",
		Enabled:    true,
		Metadata: types.Metadata{
			Name: "service-cors-test-target",
		},
		Config: types.KongCorsPluginConfig{
			Origins:        []string{"*"},
			Headers:        []string{"Content-Type"},
			Methods:        []string{"GET", "POST"},
			MaxAge:         3600,
			Credentials:    true,
			ExposedHeaders: []string{"X-Custom-Header"},
		},
	}

	result := GenerateCorsPlugin(corsConfig, targetRefName)
	if diff := deep.Equal(result, expected); diff != nil {
		t.Errorf("Difference: %v", diff)
	}
}
func TestGenerateAuthenticationPlugin(t *testing.T) {
	authConfigurations := []types.AuthConfiguration{
		{
			AuthType:          "APIKey",
			Enabled:           true,
			HeaderName:        "apikey",
			HeaderEnabled:     true,
			QueryParamEnable:  true,
			QueryParamName:    "api_key",
			SendTokenUpStream: true,
		},
		{
			AuthType:   "JWT",
			Enabled:    true,
			HeaderName: "Authorization",
		},
		{
			AuthType:          "OAuth2",
			Enabled:           true,
			HeaderName:        "Authorization",
			SendTokenUpStream: true,
		},
		{
			AuthType: "mTLS",
			Enabled:  true,
			Certificates: []types.Certificate{
				{Key: "cert1"},
				{Key: "cert2"},
			},
		},
	}
	targetRefName := "test-target"

	expected := []interface{}{
		types.KongKeyAuthPlugin{
			APIVersion: "configuration.konghq.com/v1",
			Kind:       "KongPlugin",
			Plugin:     "key-auth",
			Enabled:    true,
			Metadata: types.Metadata{
				Name: "service-key_auth-test-target",
			},
			Config: types.KongKeyAuthPluginConfig{
				HideCredentials: false,
				KeyNames:        []string{"apikey", "api_key"},
				KeyInHeader:     true,
				KeyInQuery:      true,
			},
		},
		types.KongJWTAuthPlugin{
			APIVersion: "configuration.konghq.com/v1",
			Kind:       "KongPlugin",
			Plugin:     "jwt",
			Enabled:    true,
			Metadata: types.Metadata{
				Name: "service-jwt-test-target",
			},
			Config: types.KongJWTAuthPluginConfig{
				HeaderNames: []string{"Authorization"},
			},
		},
		types.KongOAuth2AuthPlugin{
			APIVersion: "configuration.konghq.com/v1",
			Kind:       "KongPlugin",
			Plugin:     "oauth2",
			Enabled:    true,
			Metadata: types.Metadata{
				Name: "service-oauth2-test-target",
			},
			Config: types.KongOAuth2AuthPluginConfig{
				HideCredentials: false,
				AuthHeaderName:  "Authorization",
				ProvisionKey:    "d7fa738865aa3e805b12c36980a74e1b8e758c86",
			},
		},
		types.KongMTLSAuthPlugin{
			APIVersion: "configuration.konghq.com/v1",
			Kind:       "KongPlugin",
			Plugin:     "mtls-auth",
			Enabled:    true,
			Metadata: types.Metadata{
				Name: "service-mtls_auth-test-target",
			},
			Config: types.KongMTLSAuthPluginConfig{
				CACertificates: []string{"cert1", "cert2"},
			},
		},
	}

	result := GenerateAuthenticationPlugin(&authConfigurations, targetRefName, nil)
	if diff := deep.Equal(result, expected); diff != nil {
		t.Errorf("Difference: %v", diff)
	}
}
