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

package main

import (
	"apk_kong_lib/config/types"
	"apk_kong_lib/pkg/transformer"
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetUniqueIDForAPI(t *testing.T) {
	name := "test-api"
	version := "v1"
	organization := "test-org"
	expected := sha1.New()
	expected.Write([]byte("test-org-test-api-v1"))
	expectedHash := hex.EncodeToString(expected.Sum(nil))

	result := GetUniqueIDForAPI(name, version, organization)
	assert.Equal(t, expectedHash, result, "The unique ID should match the expected hash")
}

func TestGenerateRateLimitPlugin(t *testing.T) {
	k8sArtifact := transformer.K8sArtifacts{RateLimiters: make(map[string]*types.KongRateLimitPlugin)}
	rateLimit := types.RateLimit{
		Unit:            "Minute",
		RequestsPerUnit: 100,
	}
	targetRefName := "test-api"

	generateRateLimitPlugin(&k8sArtifact, rateLimit, targetRefName, nil)

	assert.NotEmpty(t, k8sArtifact.RateLimiters, "RateLimiters should not be empty")
}

func TestGenerateCorsPlugin(t *testing.T) {
	k8sArtifact := transformer.K8sArtifacts{CorsConfiguration: make(map[string]*types.KongCorsPlugin)}
	corsConfig := types.CORSConfiguration{
		AccessControlAllowOrigins: []string{"*"},
	}
	targetRefName := "test-api"

	generateCorsPlugin(&k8sArtifact, corsConfig, targetRefName)

	assert.NotEmpty(t, k8sArtifact.CorsConfiguration, "CorsConfiguration should not be empty")
}

func TestGenerateAuthenticationPlugin(t *testing.T) {
	k8sArtifact := transformer.K8sArtifacts{
		KeyAuthentications:    make(map[string]*types.KongKeyAuthPlugin),
		JWTAuthentications:    make(map[string]*types.KongJWTAuthPlugin),
		OAuth2Authentications: make(map[string]*types.KongOAuth2AuthPlugin),
		MTLSAuthentications:   make(map[string]*types.KongMTLSAuthPlugin),
	}
	authConfig := []types.AuthConfiguration{
		{
			AuthType:          "APIKey",
			Enabled:           true,
			HeaderName:        "apikey",
			HeaderEnabled:     true,
			QueryParamEnable:  true,
			QueryParamName:    "api_key",
			SendTokenUpStream: true,
		},
	}
	targetRefName := "test-api"

	generateAuthenticationPlugin(&k8sArtifact, authConfig, targetRefName, nil)

	assert.NotEmpty(t, k8sArtifact.KeyAuthentications, "KeyAuthentications should not be empty")
}
