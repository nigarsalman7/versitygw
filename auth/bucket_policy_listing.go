// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package auth

import (
	"encoding/json"
	"strings"
)

// BucketPolicyGrantsVisibility reports whether the bucket policy contains at
// least one Allow statement that names acc directly as a principal and
// targets this bucket (the bucket itself or any object pattern inside it).
//
// It is used only to decide whether a bucket shows up in ListBuckets for a
// non-owner. It does not authorize any request: every operation on the
// bucket is still checked by VerifyAccess. Conditions are ignored on purpose,
// so a bucket may be listed even if a Condition later denies a request.
// A Deny statement that names acc and covers the whole bucket ("bucket" or
// "bucket/*" with s3:* or *) hides the bucket.
func BucketPolicyGrantsVisibility(policy []byte, acc Account, bucket string) bool {
	if len(policy) == 0 {
		return false
	}

	var bp BucketPolicy
	if err := json.Unmarshal(policy, &bp); err != nil {
		return false
	}

	allowed := false
	for _, st := range bp.Statement {
		if st.Principals.matchFor(acc) != principalDirectMatch {
			continue
		}

		switch st.Effect {
		case BucketPolicyAccessTypeDeny:
			if denyCoversWholeBucket(st, bucket) {
				return false
			}
		case BucketPolicyAccessTypeAllow:
			if resourcesTouchBucket(st.Resources, bucket) {
				allowed = true
			}
		}
	}

	return allowed
}

// resourcesTouchBucket checks if any resource pattern refers to the bucket,
// either as "bucket" or as "bucket/<key pattern>".
func resourcesTouchBucket(r Resources, bucket string) bool {
	for res := range r {
		bucketPart, _, _ := strings.Cut(res, "/")
		if matchPattern(bucketPart, bucket) {
			return true
		}
	}
	return false
}

func denyCoversWholeBucket(st BucketPolicyItem, bucket string) bool {
	if !st.Actions.FindMatch(AllActions) {
		return false
	}
	_, hasBucket := st.Resources[bucket]
	_, hasObjects := st.Resources[bucket+"/*"]
	_, hasAll := st.Resources["*"]
	return hasAll || (hasBucket && hasObjects)
}
