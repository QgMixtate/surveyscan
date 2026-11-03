package config

import (
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
)

// Database reads an optional private password file without formatting the DSN or password into errors.
func Database() (*pgx.ConnConfig, error) {
	raw := os.Getenv("SURVEYSCAN_V2_DATABASE_URL")
	if raw == "" {
		return nil, errors.New("SURVEYSCAN_V2_DATABASE_URL is required")
	}
	cfg, err := pgx.ParseConfig(raw)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	if path := os.Getenv("SURVEYSCAN_V2_DATABASE_PASSWORD_FILE"); path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, errors.New("cannot read database password file")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("database password file must be private regular file <=4096 bytes")
		}
		b, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(b) == 0 || len(b) > 4096 {
			return nil, errors.New("empty, oversized or unreadable database password file")
		}
		cfg.Password = strings.TrimRight(string(b), "\r\n")
		if cfg.Password == "" {
			return nil, errors.New("empty database password")
		}
	}
	return cfg, nil
}
func ListenAddress() (string, error) {
	addr := os.Getenv("SURVEYSCAN_V2_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8082"
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", fmt.Errorf("invalid listen address")
	}
	return addr, nil
}
func BaoURL() (string, error) {
	raw := os.Getenv("SURVEYSCAN_V2_BAO_ADDR")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("valid SURVEYSCAN_V2_BAO_ADDR is required")
	}
	return strings.TrimRight(raw, "/"), nil
}
