package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Стенд R-027: ответ слияния обрывался по WriteTimeout сервера, хотя операция завершалась. assetOperationContext
// продлевает срок записи ответа — клиент получает ответ целиком при обработке дольше WriteTimeout.
func TestAssetOperationOutlivesServerWriteTimeout(t *testing.T) {
	for _, extend := range []bool{false, true} {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if extend {
				_, cancel := assetOperationContext(w, req)
				defer cancel()
			}
			time.Sleep(600 * time.Millisecond) // «операция» дольше WriteTimeout
			registryJSON(w, map[string]string{"status": "done"})
		}))
		server.Config.WriteTimeout = 200 * time.Millisecond
		server.StartTLS()
		resp, err := server.Client().Post(server.URL, "application/json", nil)
		var body []byte
		if err == nil {
			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		server.Close()
		ok := err == nil && string(body) == "{\"status\":\"done\"}\n"
		if extend && !ok {
			t.Fatal("extended operation must deliver its response", err, string(body))
		}
		if !extend && ok {
			t.Fatal("control: without extension the server must cut the response (test would prove nothing)")
		}
	}
}
