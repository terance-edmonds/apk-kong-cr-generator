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

package constants

import "github.com/terance-edmonds/wso2-apk-k8s-go-lib/config/constants"

const SANDBOX_TYPE = constants.SANDBOX_TYPE
const PRODUCTION_TYPE = constants.PRODUCTION_TYPE

const API_TYPE_REST = constants.API_TYPE_REST
const API_TYPE_GRAPHQL = constants.API_TYPE_GRAPHQL
const API_TYPE_GRPC = constants.API_TYPE_GRPC
const API_TYPE_ASYNC = constants.API_TYPE_ASYNC
const API_TYPE_SOAP = constants.API_TYPE_SOAP
const API_TYPE_SSE = constants.API_TYPE_SSE
const API_TYPE_WS = constants.API_TYPE_WS
const API_TYPE_WEBSUB = constants.API_TYPE_WEBSUB

var HTTP_DEFAULT_METHODS = []string{"get", "put", "post", "delete", "patch"}
