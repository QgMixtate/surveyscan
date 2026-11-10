// winrm-probe — диагностика NTLM-обмена с WinRM по HTTPS (стенд). Печатает каждую «ногу» обмена: схему заголовка,
// код ответа, схемы WWW-Authenticate и признак повторного использования TCP-соединения. Токены и пароль не печатаются.
//
//	winrm-probe --host 10.0.0.1 --port 5986 --server-name NAME --user 'DOM\u' --password-file F --ca-file CA.pem
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

type logging struct{ next http.RoundTripper }

func scheme(v string) string {
	if v == "" {
		return "-"
	}
	f := strings.Fields(v)
	return f[0]
}

func (l logging) RoundTrip(req *http.Request) (*http.Response, error) {
	reused := false
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	res, err := l.next.RoundTrip(req)
	if err != nil {
		fmt.Printf("  leg: Authorization=%s -> error: %v\n", scheme(req.Header.Get("Authorization")), err)
		return nil, err
	}
	var www []string
	for _, v := range res.Header.Values("Www-Authenticate") {
		www = append(www, scheme(v))
	}
	fmt.Printf("  leg: Authorization=%s -> HTTP %d %s, WWW-Authenticate=%v, conn_reused=%v, close=%v, content-type=%q\n",
		scheme(req.Header.Get("Authorization")), res.StatusCode, res.Proto, www, reused, res.Close, res.Header.Get("Content-Type"))
	return res, nil
}

func main() {
	host := flag.String("host", "", "")
	port := flag.String("port", "5986", "")
	sni := flag.String("server-name", "", "")
	user := flag.String("user", "", "")
	passFile := flag.String("password-file", "", "")
	caFile := flag.String("ca-file", "", "")
	flag.Parse()
	pass, e1 := os.ReadFile(*passFile)
	ca, e2 := os.ReadFile(*caFile)
	if e1 != nil || e2 != nil {
		fmt.Println("cannot read password/CA file")
		os.Exit(1)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: *sni, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 20 * time.Second}
	client := &http.Client{Transport: &ntlmssp.Negotiator{RoundTripper: logging{tr}}, Timeout: 40 * time.Second}
	body := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`
	req, _ := http.NewRequest("POST", "https://"+*host+":"+*port+"/wsman", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.SetBasicAuth(*user, strings.TrimRight(string(pass), "\r\n"))
	fmt.Println("request: POST /wsman, NTLM through go-ntlmssp (same as the agent)")
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("RESULT: error:", err)
		os.Exit(1)
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 300))
	fmt.Printf("RESULT: final HTTP %d, content-type=%q, body-start=%q\n", res.StatusCode, res.Header.Get("Content-Type"), strings.Join(strings.Fields(string(b)), " "))
}
