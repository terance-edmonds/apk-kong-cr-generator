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

package utils

import (
	"apk_kong_lib/config/types"
	"crypto/sha1"
	"fmt"
)

// GeneratePluginRefName generates a reference name for a plugin based on the operation, target reference, and plugin name.
func GeneratePluginRefName(operation *types.Operation, targetRef string, pluginName string) string {
	concatenatedString := pluginName
	if operation != nil {
		operationTargetHash := fmt.Sprintf("%x", sha1.Sum([]byte(operation.Target+operation.Verb)))
		concatenatedString = concatenatedString + "-" + operationTargetHash
		return "route-" + concatenatedString + "-" + targetRef
	} else {
		return "service-" + concatenatedString + "-" + targetRef
	}
}

// CheckValue checks if a value is nil and returns the default value if it is.
func CheckValue(value interface{}, defaultValue interface{}) interface{} {
	if value != nil {
		return value
	} else {
		return defaultValue
	}
}

// GenerateProvisionKey generates a provision key based on the name.
func GenerateProvisionKey(name string) string {
	hash := sha1.Sum([]byte(name))
	return fmt.Sprintf("%x", hash)
}
