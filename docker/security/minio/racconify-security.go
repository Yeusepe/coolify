package cmd

import (
    "net/http"
    "strings"
)

// The retired community release has no upstream fixes for these unused features.
// Keep ordinary signed S3 uploads available to Supabase Storage.
func rejectUnsafeLegacyS3Features(r *http.Request) bool {
    for name, values := range r.Header {
        if strings.HasPrefix(strings.ToLower(name), "x-minio-replication-") || strings.EqualFold(name, "X-Amz-Meta-Snowball-Auto-Extract") {
            return true
        }
        if strings.EqualFold(name, "X-Amz-Content-Sha256") {
            for _, value := range values {
                if strings.EqualFold(strings.TrimSpace(value), "STREAMING-UNSIGNED-PAYLOAD-TRAILER") { return true }
            }
        }
    }
    for name, values := range r.URL.Query() {
        if strings.EqualFold(name, "select") || strings.EqualFold(name, "select-type") { return true }
        if strings.EqualFold(name, "X-Amz-Content-Sha256") {
            for _, value := range values {
                if strings.EqualFold(strings.TrimSpace(value), "STREAMING-UNSIGNED-PAYLOAD-TRAILER") { return true }
            }
        }
    }
    return false
}
