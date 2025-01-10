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

package transformer

import (
	"apk_kong_lib/config/types"

	corev1 "k8s.io/api/core/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// K8sArtifacts k8s artifact representation of API
type K8sArtifacts struct {
	HTTPRoutes            map[string]*gwapiv1.HTTPRoute
	ConfigMaps            map[string]*corev1.ConfigMap
	Secrets               map[string]*corev1.Secret
	CorsConfiguration     map[string]*types.KongCorsPlugin
	RateLimiters          map[string]*types.KongRateLimitPlugin
	KeyAuthentications    map[string]*types.KongKeyAuthPlugin
	JWTAuthentications    map[string]*types.KongJWTAuthPlugin
	OAuth2Authentications map[string]*types.KongOAuth2AuthPlugin
	MTLSAuthentications   map[string]*types.KongMTLSAuthPlugin
}
