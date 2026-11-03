package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrAuth      = errors.New("authentication required")
	ErrForbidden = errors.New("forbidden")
	ErrInvalid   = errors.New("invalid input")
	ErrLimit     = errors.New("rate limited")
	ErrConflict  = errors.New("already initialized or duplicate user")
)
var usernamePattern = regexp.MustCompile(`^[a-z0-9_.@-]{1,128}$`)
var hashSlots = make(chan struct{}, 2)

type Service struct {
	pool                 *pgxpool.Pool
	dummySalt, dummyHash []byte
}

func New(pool *pgxpool.Pool) *Service {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		panic("secure randomness unavailable")
	}
	return &Service{pool: pool, dummySalt: salt, dummyHash: derive("non-user dummy credential", salt)}
}
func derive(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
}
func Digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func secret() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic("secure randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func normalize(s string) string   { return strings.ToLower(s) }
func validPassword(s string) bool { return len(s) >= 16 && len(s) <= 1024 && utf8.ValidString(s) }
func (s *Service) event(ctx context.Context, tx pgx.Tx, id port.Identity, action, object string) error {
	_, e := tx.Exec(ctx, "INSERT INTO access.security_events(event_id,tenant_id,user_id,action,object_id) VALUES($1,$2,$3,$4,$5)", identifier.New(), id.TenantID, id.UserID, action, object)
	return e
}

// Provision доступен только локальной административной консоли с DB-доступом.
func (s *Service) Provision(ctx context.Context, bootstrap bool, tenantID, tenantName, username, password, role string) error {
	username = normalize(username)
	if !identifier.Valid(tenantID) || !usernamePattern.MatchString(username) || !validPassword(password) || (role != "admin" && role != "operator" && role != "viewer") || bootstrap && (role != "admin" || len(tenantName) == 0 || len(tenantName) > 512) {
		return ErrInvalid
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return e
	}
	hash := derive(password, salt)
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(734933406)"); e != nil {
		return e
	}
	if bootstrap {
		var exists bool
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access.users) OR EXISTS(SELECT 1 FROM access.bootstrap_state)").Scan(&exists)
		if e != nil {
			return e
		}
		if exists {
			return ErrConflict
		}
		if _, e = tx.Exec(ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,$2,'active')", tenantID, tenantName); e != nil {
			return ErrConflict
		}
	}
	var active bool
	if e = tx.QueryRow(ctx, "SELECT status='active' FROM access.tenants WHERE tenant_id=$1 FOR SHARE", tenantID).Scan(&active); e != nil || !active {
		return ErrInvalid
	}
	userID := identifier.New()
	_, e = tx.Exec(ctx, "INSERT INTO access.users(user_id,tenant_id,username,password_salt,password_hash,role) VALUES($1,$2,$3,$4,$5,$6)", userID, tenantID, username, salt, hash, role)
	if e != nil {
		return ErrConflict
	}
	if bootstrap {
		if _, e = tx.Exec(ctx, "INSERT INTO access.bootstrap_state(singleton,tenant_id,user_id) VALUES(true,$1,$2)", tenantID, userID); e != nil {
			return e
		}
	}
	if e = s.event(ctx, tx, port.Identity{TenantID: tenantID, UserID: userID}, "console.user_created", userID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// ChangeUser меняет metadata и немедленно инвалидирует выданные credentials revision-guard'ом.
func (s *Service) ChangeUser(ctx context.Context, tenantID, username, role string, enabled bool) error {
	if !identifier.Valid(tenantID) || (role != "admin" && role != "operator" && role != "viewer") {
		return ErrInvalid
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var userID string
	e = tx.QueryRow(ctx, "UPDATE access.users SET role=$3,enabled=$4,revision=revision+1 WHERE tenant_id=$1 AND username=$2 RETURNING user_id::text", tenantID, normalize(username), role, enabled).Scan(&userID)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrInvalid
	}
	if e != nil {
		return e
	}
	if e = s.event(ctx, tx, port.Identity{TenantID: tenantID, UserID: userID}, "console.user_changed", userID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Service) rate(ctx context.Context, username string) error {
	for _, limit := range []struct {
		key string
		max int
	}{{"all", 120}, {"account:" + Digest(username), 10}} {
		var count int
		e := s.pool.QueryRow(ctx, `INSERT INTO access.login_buckets(bucket,window_id,attempts) VALUES($1,floor(extract(epoch FROM clock_timestamp())/60)::bigint,1) ON CONFLICT(bucket) DO UPDATE SET window_id=excluded.window_id,attempts=CASE WHEN access.login_buckets.window_id=excluded.window_id THEN access.login_buckets.attempts+1 ELSE 1 END RETURNING attempts`, limit.key).Scan(&count)
		if e != nil {
			return e
		}
		if count > limit.max {
			return ErrLimit
		}
	}
	_, e := s.pool.Exec(ctx, "DELETE FROM access.login_buckets WHERE window_id < floor(extract(epoch FROM clock_timestamp())/60)::bigint-2")
	return e
}

type Session struct {
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	Roles     []string  `json:"roles"`
	ExpiresAt time.Time `json:"expires_at"`
	CSRFToken string    `json:"csrf_token"`
}

func (s *Service) Login(ctx context.Context, username, password string) (Session, string, error) {
	username = normalize(username)
	if !usernamePattern.MatchString(username) || len(password) < 1 || len(password) > 1024 {
		return Session{}, "", ErrAuth
	}
	if e := s.rate(ctx, username); e != nil {
		return Session{}, "", e
	}
	select {
	case hashSlots <- struct{}{}:
		defer func() { <-hashSlots }()
	default:
		return Session{}, "", ErrLimit
	}
	var userID, tenantID, role, revision string
	var salt, stored []byte
	var enabled bool
	e := s.pool.QueryRow(ctx, `SELECT u.user_id::text,u.tenant_id::text,u.role,u.revision::text,u.password_salt,u.password_hash,u.enabled AND t.status='active' FROM access.users u JOIN access.tenants t USING(tenant_id) WHERE username=$1`, username).Scan(&userID, &tenantID, &role, &revision, &salt, &stored, &enabled)
	missing := errors.Is(e, pgx.ErrNoRows)
	if e != nil && !missing {
		return Session{}, "", e
	}
	if missing {
		salt = s.dummySalt
		stored = s.dummyHash
	}
	match := subtle.ConstantTimeCompare(derive(password, salt), stored) == 1
	if !match || missing || !enabled {
		return Session{}, "", ErrAuth
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return Session{}, "", e
	}
	defer tx.Rollback(ctx)
	var current bool
	e = tx.QueryRow(ctx, `SELECT u.enabled AND u.revision::text=$2 AND t.status='active' FROM access.users u JOIN access.tenants t USING(tenant_id) WHERE u.user_id=$1 FOR UPDATE OF u FOR SHARE OF t`, userID, revision).Scan(&current)
	if e != nil {
		return Session{}, "", e
	}
	if !current {
		return Session{}, "", ErrAuth
	}
	var active int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM access.credentials WHERE user_id=$1 AND kind='session' AND revoked_at IS NULL AND expires_at>clock_timestamp() AND user_revision::text=$2", userID, revision).Scan(&active); e != nil {
		return Session{}, "", e
	}
	if active >= 5 {
		return Session{}, "", ErrLimit
	}
	raw, csrf, id := secret(), secret(), identifier.New()
	var expires time.Time
	e = tx.QueryRow(ctx, "INSERT INTO access.credentials(credential_id,tenant_id,user_id,user_revision,kind,secret_hash,csrf_hash,name,expires_at) VALUES($1,$2,$3,$4,'session',$5,$6,'browser',clock_timestamp()+interval '8 hours') RETURNING expires_at", id, tenantID, userID, revision, Digest(raw), Digest(csrf)).Scan(&expires)
	if e != nil {
		return Session{}, "", e
	}
	if e = s.event(ctx, tx, port.Identity{TenantID: tenantID, UserID: userID}, "session.created", id); e != nil {
		return Session{}, "", e
	}
	if e = tx.Commit(ctx); e != nil {
		return Session{}, "", e
	}
	return Session{userID, tenantID, []string{role}, expires.UTC(), csrf}, raw, nil
}

const identitySQL = `SELECT c.tenant_id::text,c.user_id::text,c.credential_id::text,u.role,c.kind,c.scopes,c.csrf_hash FROM access.credentials c JOIN access.users u ON u.tenant_id=c.tenant_id AND u.user_id=c.user_id JOIN access.tenants t ON t.tenant_id=u.tenant_id WHERE c.revoked_at IS NULL AND c.expires_at>clock_timestamp() AND u.enabled AND t.status='active' AND c.user_revision=u.revision AND `

type rowQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func identity(ctx context.Context, q rowQuery, where string, args ...any) (port.Identity, string, error) {
	var id port.Identity
	var csrf *string
	e := q.QueryRow(ctx, identitySQL+where, args...).Scan(&id.TenantID, &id.UserID, &id.CredentialID, &id.Role, &id.Kind, &id.Scopes, &csrf)
	if errors.Is(e, pgx.ErrNoRows) {
		return id, "", ErrAuth
	}
	if e != nil {
		return id, "", e
	}
	if csrf != nil {
		return id, *csrf, nil
	}
	return id, "", nil
}
func (s *Service) Authenticate(ctx context.Context, raw, kind, csrf string, mutation bool) (port.Identity, error) {
	if len(raw) != 43 {
		return port.Identity{}, ErrAuth
	}
	id, stored, e := identity(ctx, s.pool, "c.secret_hash=$1 AND c.kind=$2", Digest(raw), kind)
	if e != nil {
		return id, e
	}
	if mutation && kind == "session" && subtle.ConstantTimeCompare([]byte(stored), []byte(Digest(csrf))) != 1 {
		return id, ErrForbidden
	}
	return id, nil
}
func allowed(id port.Identity, action string) bool {
	if (id.Kind != "session" && id.Kind != "cli") || (id.Role != "admin" && id.Role != "operator" && id.Role != "viewer") {
		return false
	}
	if id.Kind == "cli" {
		if action != "assets:read" && action != "sources:read" {
			return false
		}
		for _, s := range id.Scopes {
			if s == action {
				return true
			}
		}
		return false
	}
	switch action {
	case "assets:read", "sources:read", "jobs:read", "auth:self":
		return true
	case "assets:write", "jobs:write":
		return id.Role == "admin" || id.Role == "operator"
	case "sources:admin":
		return id.Role == "admin"
	}
	return false
}
func (s *Service) Authorize(ctx context.Context, tx pgx.Tx, credentialID, tenantID, action string) (port.Identity, error) {
	if !identifier.Valid(credentialID) || !identifier.Valid(tenantID) {
		return port.Identity{}, ErrForbidden
	}

	// Всегда user → credential: logout/revoke сначала блокируют user.
	// Иначе ожидающий user-lock worker удерживает credential и блокирует отзыв.
	var owner, credentialTenant string
	e := tx.QueryRow(ctx, "SELECT user_id::text,tenant_id::text FROM access.credentials WHERE credential_id=$1", credentialID).Scan(&owner, &credentialTenant)
	if errors.Is(e, pgx.ErrNoRows) {
		return port.Identity{}, ErrAuth
	}
	if e != nil {
		return port.Identity{}, e
	}
	if credentialTenant != tenantID {
		return port.Identity{}, ErrForbidden
	}
	var locked string
	e = tx.QueryRow(ctx, "SELECT user_id::text FROM access.users WHERE user_id=$1 FOR SHARE", owner).Scan(&locked)
	if errors.Is(e, pgx.ErrNoRows) {
		return port.Identity{}, ErrAuth
	}
	if e != nil {
		return port.Identity{}, e
	}
	id, _, e := identity(ctx, tx, "c.credential_id=$1 FOR SHARE OF c,u,t", credentialID)
	if e != nil {
		return id, e
	}
	if id.TenantID != tenantID || !allowed(id, action) {
		return id, ErrForbidden
	}
	return id, nil
}
func (s *Service) lockUser(ctx context.Context, tx pgx.Tx, id port.Identity) error {
	var found string
	e := tx.QueryRow(ctx, "SELECT user_id::text FROM access.users WHERE user_id=$1 AND tenant_id=$2 FOR UPDATE", id.UserID, id.TenantID).Scan(&found)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrAuth
	}
	return e
}
func (s *Service) Logout(ctx context.Context, id port.Identity) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = s.lockUser(ctx, tx, id); e != nil {
		return e
	}
	if _, e = s.Authorize(ctx, tx, id.CredentialID, id.TenantID, "auth:self"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE access.credentials SET revoked_at=clock_timestamp() WHERE credential_id=$1", id.CredentialID); e != nil {
		return e
	}
	if e = s.event(ctx, tx, id, "session.revoked", id.CredentialID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

type TokenRequest struct {
	Name             string   `json:"name"`
	ExpiresInSeconds int      `json:"expires_in_seconds"`
	Scopes           []string `json:"scopes"`
}
type TokenResult struct {
	TokenID   string    `json:"token_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) CreateToken(ctx context.Context, id port.Identity, r TokenRequest) (TokenResult, error) {
	if id.Kind != "session" || len(r.Name) < 1 || len(r.Name) > 128 || r.ExpiresInSeconds < 60 || r.ExpiresInSeconds > 86400 || len(r.Scopes) < 1 || len(r.Scopes) > 2 {
		return TokenResult{}, ErrInvalid
	}
	seen := map[string]bool{}
	for _, sc := range r.Scopes {
		if (sc != "assets:read" && sc != "sources:read") || seen[sc] {
			return TokenResult{}, ErrInvalid
		}
		seen[sc] = true
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return TokenResult{}, e
	}
	defer tx.Rollback(ctx)
	if e = s.lockUser(ctx, tx, id); e != nil {
		return TokenResult{}, e
	}
	current, e := s.Authorize(ctx, tx, id.CredentialID, id.TenantID, "auth:self")
	if e != nil {
		return TokenResult{}, e
	}
	// FOR UPDATE сериализует выдачу токенов одного пользователя и ограничение количества.
	var revision string
	e = tx.QueryRow(ctx, "SELECT revision::text FROM access.users WHERE user_id=$1 FOR UPDATE", current.UserID).Scan(&revision)
	if e != nil {
		return TokenResult{}, e
	}
	var count int
	e = tx.QueryRow(ctx, "SELECT count(*) FROM access.credentials WHERE user_id=$1 AND kind='cli' AND revoked_at IS NULL AND expires_at>clock_timestamp() AND user_revision::text=$2", current.UserID, revision).Scan(&count)
	if e != nil {
		return TokenResult{}, e
	}
	if count >= 10 {
		return TokenResult{}, ErrLimit
	}
	result := TokenResult{TokenID: identifier.New(), Token: secret()}
	e = tx.QueryRow(ctx, "INSERT INTO access.credentials(credential_id,tenant_id,user_id,user_revision,kind,secret_hash,name,scopes,expires_at) VALUES($1,$2,$3,$4,'cli',$5,$6,$7,clock_timestamp()+$8*interval '1 second') RETURNING expires_at", result.TokenID, current.TenantID, current.UserID, revision, Digest(result.Token), r.Name, r.Scopes, r.ExpiresInSeconds).Scan(&result.ExpiresAt)
	if e != nil {
		return TokenResult{}, e
	}
	result.ExpiresAt = result.ExpiresAt.UTC()
	if e = s.event(ctx, tx, current, "cli_token.created", result.TokenID); e != nil {
		return TokenResult{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return TokenResult{}, e
	}
	return result, nil
}
func (s *Service) RevokeToken(ctx context.Context, id port.Identity, tokenID string) error {
	if !identifier.Valid(tokenID) {
		return ErrInvalid
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = s.lockUser(ctx, tx, id); e != nil {
		return e
	}
	if _, e = s.Authorize(ctx, tx, id.CredentialID, id.TenantID, "auth:self"); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, "UPDATE access.credentials SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE credential_id=$1 AND tenant_id=$2 AND user_id=$3 AND kind='cli'", tokenID, id.TenantID, id.UserID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrForbidden
	}
	if e = s.event(ctx, tx, id, "cli_token.revoked", tokenID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *Service) ResetPassword(ctx context.Context, tenantID, username, password string) error {
	if !identifier.Valid(tenantID) || !validPassword(password) {
		return ErrInvalid
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return e
	}
	hash := derive(password, salt)
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var userID string
	e = tx.QueryRow(ctx, "UPDATE access.users SET password_salt=$3,password_hash=$4,revision=revision+1 WHERE tenant_id=$1 AND username=$2 RETURNING user_id::text", tenantID, normalize(username), salt, hash).Scan(&userID)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrInvalid
	}
	if e != nil {
		return e
	}
	if e = s.event(ctx, tx, port.Identity{TenantID: tenantID, UserID: userID}, "console.password_reset", userID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

var _ port.Authorizer = (*Service)(nil)
