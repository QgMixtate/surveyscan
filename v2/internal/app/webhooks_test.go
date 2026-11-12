package app

import (
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
)

func TestWebhookURLAndBackoff(t *testing.T) {
	for url, ok := range map[string]bool{"https://itsm.example.test/hook": true, "http://127.0.0.1:9000/x": true, "http://localhost:9/x": true, "http://[::1]:9/x": true,
		"http://itsm.example.test/hook": false, "https://u:p@itsm.example.test/": false, "https://itsm.example.test/#f": false, "ftp://itsm.example.test/x": false, "https:///x": false} {
		if validWebhookURL(url) != ok {
			t.Fatal(url)
		}
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute}
	for i, d := range want {
		if messaging.WebhookBackoff(i+1) != d {
			t.Fatal(i+1, messaging.WebhookBackoff(i+1))
		}
	}
	if messaging.WebhookBackoff(50) != time.Hour {
		t.Fatal("cap")
	}
	if WebhookSignature([]byte("k"), "1", []byte("{}")) != "v1=3dd49b2593d0f9a349e9e71c4bde3e2b862c2be4003fe9b4ba81332029310158" { // HMAC-SHA256("k", "1.{}")
		t.Fatal("signature vector")
	}
}
