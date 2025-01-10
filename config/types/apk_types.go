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

import "github.com/terance-edmonds/wso2-apk-k8s-go-lib/config/types"

// SecretInfo holds the info related to the created secret upon enabling the endpoint security options like basic auth
type SecretInfo = types.SecretInfo

// EndpointSecurity comtains the information related to endpoint security configurations enabled by a user for a given API
type EndpointSecurity = types.EndpointSecurity

// EndpointCertificate struct stores the the alias and the name for a particular endpoint security configuration
type EndpointCertificate = types.EndpointCertificate

// EndpointDetails represents the details of an endpoint, containing its URL.
type EndpointDetails = types.EndpointDetails

// EndpointConfiguration stores the data related to endpoints and their related
type EndpointConfiguration = types.EndpointConfiguration

// AIRatelimit defines the configuration for AI rate limiting,
// including whether rate limiting is enabled and the settings
// for token and request-based limits.
type AIRatelimit = types.AIRatelimit

// TokenAIRL defines the configuration for Token AI rate limit settings.
type TokenAIRL = types.TokenAIRL

// RequestAIRL defines the configuration for Request AI rate limit settings.
type RequestAIRL = types.RequestAIRL

// AdditionalProperty stores the custom properties set by the user for a particular API
type AdditionalProperty = types.AdditionalProperty

// Certificate struct stores the the alias and the name for a particular mTLS configuration
type Certificate = types.Certificate

// AuthConfiguration represents the security configurations made for the API security
type AuthConfiguration = types.AuthConfiguration

// EndpointConfigurations holds production and sandbox endpoints.
type EndpointConfigurations = types.EndpointConfigurations

// OperationPolicy defines policies, including interceptor parameters, for API operations.
type OperationPolicy = types.OperationPolicy

// Parameter interface is used to define the type of parameters that can be used in an operation policy.
type Parameter = types.Parameter

// RedirectPolicy contains the information for redirect request policies
type RedirectPolicy = types.RedirectPolicy

// URLList contains the urls for mirror policies
type URLList = types.URLList

// Header contains the information for header modification
type Header = types.Header

// InterceptorService holds configuration details for configuring interceptor
// for particular API requests or responses.
type InterceptorService = types.InterceptorService

// BackendJWT holds configuration details for configuring JWT for backend
type BackendJWT = types.BackendJWT

// OperationPolicies organizes request and response policies for an API operation.
type OperationPolicies = types.OperationPolicies

// Operation represents an API operation with target, verb, scopes, security, and associated policies.
type Operation = types.Operation

// RateLimit is a placeholder for future rate-limiting configuration.
type RateLimit = types.RateLimit

// VHost defines virtual hosts for production and sandbox environments.
type VHost = types.VHost

// AIProvider represents the AI provider configuration.
type AIProvider = types.AIProvider

// CORSConfiguration represents the CORS (Cross-Origin Resource Sharing) configuration for an API.
type CORSConfiguration = types.CORSConfiguration

// API represents an main API type definition
type APKConf = types.APKConf

// Organization represents an organization configuration.
type Organization = types.Organization

// OrganizationProperty represents a custom property for an organization.
type OrganizationProperty = types.OrganizationProperty
