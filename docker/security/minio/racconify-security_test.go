package cmd

import (
    "net/http/httptest"
    "testing"
)

func TestLegacyS3Guards(t *testing.T) {
    for _, test := range []struct { name, url, header, value string; blocked bool }{
        {"ordinary signed upload", "/bucket/object", "X-Amz-Content-Sha256", "abc123", false},
        {"signed streaming", "/bucket/object", "X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", false},
        {"unsigned header", "/bucket/object", "X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", true},
        {"unsigned query", "/bucket/object?X-Amz-Content-Sha256=STREAMING-UNSIGNED-PAYLOAD-TRAILER", "", "", true},
        {"replication injection", "/bucket/object", "X-Minio-Replication-Server-Side-Encryption-Sealed-Key", "forged", true},
        {"snowball", "/bucket/object", "X-Amz-Meta-Snowball-Auto-Extract", "true", true},
        {"select", "/bucket/object?select&select-type=2", "", "", true},
        {"read", "/bucket/object?versionId=123", "", "", false},
    } {
        t.Run(test.name, func(t *testing.T) {
            r := httptest.NewRequest("PUT", test.url, nil)
            if test.header != "" { r.Header.Set(test.header, test.value) }
            if got := rejectUnsafeLegacyS3Features(r); got != test.blocked { t.Fatalf("blocked=%v, want %v", got, test.blocked) }
        })
    }
}
