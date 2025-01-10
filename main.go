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
	"apk_kong_lib/config/constants"
	"apk_kong_lib/config/types"
	"apk_kong_lib/pkg/generators"
	"apk_kong_lib/pkg/transformer"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	http_generator "github.com/terance-edmonds/wso2-apk-k8s-go-lib/pkg/generators/http"
	"github.com/terance-edmonds/wso2-apk-k8s-go-lib/pkg/utils"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func main() {
	k8sArtifact := transformer.K8sArtifacts{HTTPRoutes: make(map[string]*gwapiv1.HTTPRoute), ConfigMaps: make(map[string]*corev1.ConfigMap), Secrets: make(map[string]*corev1.Secret), RateLimiters: make(map[string]*types.KongRateLimitPlugin), CorsConfiguration: make(map[string]*types.KongCorsPlugin), KeyAuthentications: make(map[string]*types.KongKeyAuthPlugin), JWTAuthentications: make(map[string]*types.KongJWTAuthPlugin), OAuth2Authentications: make(map[string]*types.KongOAuth2AuthPlugin), MTLSAuthentications: make(map[string]*types.KongMTLSAuthPlugin)}

	var apkConf types.APKConf
	yamlFile, err := os.ReadFile("./assets/EmployeeService.apk-conf")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &apkConf)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	organizationID := "test-organization-id"
	apiUniqueID := GetUniqueIDForAPI(apkConf.Name, apkConf.Version, organizationID)

	createdEndpoints := utils.GetEndpoints(apkConf)

	// HTTPRoute
	// Generate production http routes
	if endpoints, ok := createdEndpoints[constants.PRODUCTION_TYPE]; ok {
		generateHttpRoutes(&k8sArtifact, &apkConf, organizationID, endpoints, constants.PRODUCTION_TYPE, apiUniqueID)
	}
	// Generate sandbox http routes
	if endpoints, ok := createdEndpoints[constants.SANDBOX_TYPE]; ok {
		generateHttpRoutes(&k8sArtifact, &apkConf, organizationID, endpoints, constants.SANDBOX_TYPE, apiUniqueID)
	}

	// Generate rate limit plugin
	if apkConf.RateLimit != nil {
		generateRateLimitPlugin(&k8sArtifact, *apkConf.RateLimit, apiUniqueID, nil)
	}

	// Generate CORS plugin
	if apkConf.CorsConfig != nil {
		generateCorsPlugin(&k8sArtifact, *apkConf.CorsConfig, apiUniqueID)
	}

	// Generate Authentication plugins
	if apkConf.Authentication != nil {
		generateAuthenticationPlugin(&k8sArtifact, *apkConf.Authentication, apiUniqueID, nil)
	}

	// Write to yaml files in folder tmp
	writeK8sArtifactsToFiles(&k8sArtifact)
}

func writeK8sArtifactsToFiles(k8sArtifact *transformer.K8sArtifacts) {
	// Create tmp folder if it does not exist
	if _, err := os.Stat("./tmp"); os.IsNotExist(err) {
		os.Mkdir("./tmp", 0755)
	}

	// Write http routes to yaml files
	for _, httpRoute := range k8sArtifact.HTTPRoutes {
		marshalJsonAndWriteToFile(httpRoute, httpRoute.ObjectMeta.Name)
	}

	// Write rate limit plugins to yaml files
	for _, rateLimitPlugin := range k8sArtifact.RateLimiters {
		marshalAndWriteToFile(rateLimitPlugin, rateLimitPlugin.Metadata.Name)
	}

	// Write CORS plugins to yaml files
	for _, corsPlugin := range k8sArtifact.CorsConfiguration {
		marshalAndWriteToFile(corsPlugin, corsPlugin.Metadata.Name)
	}

	// Write key authentication plugins to yaml files
	for _, keyAuthPlugin := range k8sArtifact.KeyAuthentications {
		marshalAndWriteToFile(keyAuthPlugin, keyAuthPlugin.Metadata.Name)
	}

	// Write jwt authentication plugins to yaml files
	for _, jwtAuthPlugin := range k8sArtifact.JWTAuthentications {
		marshalAndWriteToFile(jwtAuthPlugin, jwtAuthPlugin.Metadata.Name)
	}

	// Write OAuth2 authentication plugins to yaml files
	for _, oauth2AuthPlugin := range k8sArtifact.OAuth2Authentications {
		marshalAndWriteToFile(oauth2AuthPlugin, oauth2AuthPlugin.Metadata.Name)
	}

	// Write mTLS authentication plugins to yaml files
	for _, mtlsAuthPlugin := range k8sArtifact.MTLSAuthentications {
		marshalAndWriteToFile(mtlsAuthPlugin, mtlsAuthPlugin.Metadata.Name)
	}
}

// marshalAndWriteToFile marshals the given object and writes it to a file
func marshalJsonAndWriteToFile(obj interface{}, fileName string) {
	jsonData, err := json.Marshal(obj)
	if err != nil {
		log.Fatalf("Error marshalling object: %v", err)
	}
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(jsonData, &yamlData); err != nil {
		log.Fatalf("Error marshalling object: %v", err)
	}

	objYaml, err := yaml.Marshal(yamlData)
	if err != nil {
		log.Fatalf("Error marshalling object: %v", err)
	}
	err = os.WriteFile(fmt.Sprintf("./tmp/%s.yaml", fileName), objYaml, 0644)
	if err != nil {
		log.Fatalf("Error writing object: %v", err)
	}
}

// marshalAndWriteToFile marshals the given object and writes it to a file
func marshalAndWriteToFile(obj interface{}, fileName string) {
	objYaml, err := yaml.Marshal(obj)
	if err != nil {
		log.Fatalf("Error marshalling object: %v", err)
	}
	err = os.WriteFile(fmt.Sprintf("./tmp/%s.yaml", fileName), objYaml, 0644)
	if err != nil {
		log.Fatalf("Error writing object: %v", err)
	}
}

// GetUniqueIDForAPI will generate a unique ID for newly created APIs
func GetUniqueIDForAPI(name, version, organization string) string {
	concatenatedString := strings.Join([]string{organization, name, version}, "-")
	hash := sha1.New()
	hash.Write([]byte(concatenatedString))
	hashedValue := hash.Sum(nil)
	return hex.EncodeToString(hashedValue)
}

func generateHttpRoutes(k8sArtifact *transformer.K8sArtifacts, apkConf *types.APKConf, organizationID string, endpoints types.EndpointDetails, endpointType string, uniqueId string) {
	gen := http_generator.Generator()
	organization := types.Organization{
		Name: organizationID,
	}
	gatewayConfigurations := types.GatewayConfigurations{
		Name:         "kong",
		ListenerName: "http",
	}

	operationsArray := make([][]types.Operation, (len(*apkConf.Operations)+8)/8)
	row := 0
	column := 0
	for i := range operationsArray {
		operationsArray[i] = make([]types.Operation, 8)
	}
	for i := 0; i < len(*apkConf.Operations); i++ {
		if column > 7 {
			row += 1
			column = 0
		}
		operationsArray[row][column] = (*apkConf.Operations)[i]
		column += 1
	}

	for i, operations := range operationsArray {
		httpRoute, err := gen.GenerateHTTPRoute(*apkConf, organization, gatewayConfigurations, operations, &endpoints, endpointType, uniqueId, i)
		if err != nil {
			log.Printf("Error while generating http route: Error: %+v. \n", err)
		} else {
			k8sArtifact.HTTPRoutes[httpRoute.ObjectMeta.Name] = httpRoute
		}
	}
}

// generateRateLimitPlugin generates rate limit plugin
func generateRateLimitPlugin(k8sArtifact *transformer.K8sArtifacts, rateLimit types.RateLimit, targetRefName string, operation *types.Operation) {
	kongRateLimitPlugin := generators.GenerateRateLimitPlugin(rateLimit, targetRefName, operation)
	k8sArtifact.RateLimiters[kongRateLimitPlugin.Metadata.Name] = &kongRateLimitPlugin
}

// generateCorsPlugin generates CORS plugin
func generateCorsPlugin(k8sArtifact *transformer.K8sArtifacts, corsConfiguration types.CORSConfiguration, targetRefName string) {
	kongCorsPlugin := generators.GenerateCorsPlugin(corsConfiguration, targetRefName)
	k8sArtifact.CorsConfiguration[kongCorsPlugin.Metadata.Name] = &kongCorsPlugin
}

// generateAuthenticationPlugin generates authentication plugin
func generateAuthenticationPlugin(k8sArtifact *transformer.K8sArtifacts, authentications []types.AuthConfiguration, targetRefName string, operation *types.Operation) {
	authenticationPlugins := generators.GenerateAuthenticationPlugin(&authentications, targetRefName, operation)
	for _, plugin := range authenticationPlugins {
		switch plugin := plugin.(type) {
		case types.KongKeyAuthPlugin:
			k8sArtifact.KeyAuthentications[plugin.Metadata.Name] = &plugin
		case types.KongJWTAuthPlugin:
			k8sArtifact.JWTAuthentications[plugin.Metadata.Name] = &plugin
		case types.KongOAuth2AuthPlugin:
			k8sArtifact.OAuth2Authentications[plugin.Metadata.Name] = &plugin
		case types.KongMTLSAuthPlugin:
			k8sArtifact.MTLSAuthentications[plugin.Metadata.Name] = &plugin
		default:
			fmt.Println("Unknown authentication plugin type")
		}
	}
}
