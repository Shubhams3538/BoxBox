package service

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jR4dh3y/BoxBox/backend/internal/config"
	"github.com/jR4dh3y/BoxBox/backend/internal/pkg/filesystem"
	"github.com/spf13/afero"
)

func TestLoginPersistsActiveSessionBeforeReturningTokens(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := newTestAuthServiceAt(t, dataDir)
	pair, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	store, err := os.ReadFile(filepath.Join(dataDir, config.AuthSessionsFileName))
	if err != nil {
		t.Fatalf("read active session store: %v", err)
	}
	if strings.Contains(string(store), pair.AccessToken) || strings.Contains(string(store), pair.RefreshToken) {
		t.Fatal("active session store contains a raw JWT")
	}

	second := newTestAuthServiceAt(t, dataDir)
	if _, err := second.ValidateAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("access token after restart: %v", err)
	}
	if _, err := second.ValidateRefreshToken(pair.RefreshToken); err != nil {
		t.Fatalf("refresh token after restart: %v", err)
	}
}

func TestLegacyRevocationFileIsInertAndLegacyTokenIsRejected(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	_ = newTestAuthServiceAt(t, dataDir)
	legacyPath := filepath.Join(dataDir, "auth-revocations.json")
	legacyContent := `{"version":1,"revokedRefresh":{},"revokedAccess":{}}`
	if err := os.WriteFile(legacyPath, []byte(legacyContent), 0o600); err != nil {
		t.Fatalf("write legacy store fixture: %v", err)
	}

	service := newTestAuthServiceAt(t, dataDir)
	legacyClaims := Claims{
		UserID:    generateUserID("admin"),
		Username:  "admin",
		TokenType: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        generateTokenID(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "boxbox",
			Subject:   "admin",
		},
	}
	if _, err := service.ValidateToken(issueTestToken(t, legacyClaims)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("legacy token without session binding = %v, want invalid", err)
	}
	storedLegacy, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatalf("legacy store was removed: %v", err)
	}
	if string(storedLegacy) != legacyContent {
		t.Fatalf("legacy store changed: %s", storedLegacy)
	}
}

func TestRefreshRotationPersistsCurrentTokenAndStableSession(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := newTestAuthServiceAt(t, dataDir)
	original, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	replacement, err := first.Refresh(context.Background(), original.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	second := newTestAuthServiceAt(t, dataDir)
	if _, err := second.ValidateRefreshToken(original.RefreshToken); !errors.Is(err, ErrRefreshSuperseded) {
		t.Fatalf("old refresh after restart = %v, want superseded", err)
	}
	if _, err := second.ValidateRefreshToken(replacement.RefreshToken); err != nil {
		t.Fatalf("current refresh after restart: %v", err)
	}
	oldAccess, err := second.ValidateAccessToken(original.AccessToken)
	if err != nil {
		t.Fatalf("old access after restart: %v", err)
	}
	newAccess, err := second.ValidateAccessToken(replacement.AccessToken)
	if err != nil {
		t.Fatalf("new access after restart: %v", err)
	}
	if oldAccess.SessionID != newAccess.SessionID {
		t.Fatal("refresh rotation persisted a different session")
	}
}

func TestLogoutAfterRotationInvalidatesOldAccessAfterRestart(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := newTestAuthServiceAt(t, dataDir)
	original, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	independent, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("independent login: %v", err)
	}
	replacement, err := first.Refresh(context.Background(), original.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := first.Logout(context.Background(), replacement.RefreshToken); err != nil {
		t.Fatalf("logout current refresh: %v", err)
	}

	second := newTestAuthServiceAt(t, dataDir)
	for _, token := range []string{original.AccessToken, replacement.AccessToken, replacement.RefreshToken} {
		if _, err := second.ValidateToken(token); !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("token from logged-out session after restart = %v, want inactive", err)
		}
	}
	if _, err := second.ValidateAccessToken(independent.AccessToken); err != nil {
		t.Fatalf("logout affected independent session after restart: %v", err)
	}
}

func TestMissingStoreAfterRestartFailsClosed(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := newTestAuthServiceAt(t, dataDir)
	pair, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	storePath := filepath.Join(dataDir, config.AuthSessionsFileName)
	if err := os.Remove(storePath); err != nil {
		t.Fatalf("remove session store: %v", err)
	}
	if _, err := first.ValidateAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("deleting the file changed the running registry: %v", err)
	}

	second := newTestAuthServiceAt(t, dataDir)
	for _, token := range []string{pair.AccessToken, pair.RefreshToken} {
		if _, err := second.ValidateToken(token); !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("credential after restart with missing store = %v, want inactive session", err)
		}
	}
	fresh, err := second.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("fresh login after empty-store initialization: %v", err)
	}
	if _, err := second.ValidateAccessToken(fresh.AccessToken); err != nil {
		t.Fatalf("fresh login did not establish a new active session: %v", err)
	}
}

func TestSessionDeadlineDoesNotShrinkAcrossRestartRotation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	cfg := testAuthConfig(t, dataDir)
	cfg.AccessTokenExpiry = 30 * time.Minute
	cfg.RefreshTokenExpiry = 24 * time.Hour
	first := newTestAuthServiceWithConfig(t, cfg)
	original, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	claims, err := first.ValidateRefreshToken(original.RefreshToken)
	if err != nil {
		t.Fatalf("validate initial refresh: %v", err)
	}
	originalDeadline := first.sessions[claims.SessionID].ExpiresAt

	shorter := testAuthConfig(t, dataDir)
	shorter.AccessTokenExpiry = time.Second
	shorter.RefreshTokenExpiry = time.Second
	second := newTestAuthServiceWithConfig(t, shorter)
	_, err = second.Refresh(context.Background(), original.RefreshToken)
	if err != nil {
		t.Fatalf("rotate refresh after TTL shrink: %v", err)
	}
	if got := second.sessions[claims.SessionID].ExpiresAt; !got.Equal(originalDeadline) {
		t.Fatalf("session deadline shrank from %v to %v", originalDeadline, got)
	}
	if _, err := second.ValidateAccessToken(original.AccessToken); err != nil {
		t.Fatalf("old access token lost membership after shorter-TTL rotation: %v", err)
	}

	third := newTestAuthServiceAt(t, dataDir)
	if _, err := third.ValidateAccessToken(original.AccessToken); err != nil {
		t.Fatalf("old access token lost membership after restart: %v", err)
	}
}

func TestExpiredSessionCleanupRemovesOnlyExpiredSession(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	service := newTestAuthServiceAt(t, dataDir)
	expired, err := service.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login for expired session: %v", err)
	}
	active, err := service.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login for active session: %v", err)
	}
	expiredClaims, err := service.ValidateAccessToken(expired.AccessToken)
	if err != nil {
		t.Fatalf("validate session before expiry: %v", err)
	}
	service.mu.Lock()
	record := service.sessions[expiredClaims.SessionID]
	record.ExpiresAt = time.Now().Add(-time.Second)
	service.sessions[expiredClaims.SessionID] = record
	service.mu.Unlock()
	if _, err := service.ValidateAccessToken(expired.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("expired session validation = %v, want inactive", err)
	}

	if err := service.cleanupExpiredSessions(); err != nil {
		t.Fatalf("cleanup expired sessions: %v", err)
	}
	restarted := newTestAuthServiceAt(t, dataDir)
	if _, err := restarted.ValidateAccessToken(expired.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("expired session survived cleanup/restart: %v", err)
	}
	if _, err := restarted.ValidateAccessToken(active.AccessToken); err != nil {
		t.Fatalf("cleanup removed an unexpired session: %v", err)
	}
}

func TestConcurrentRefreshHasOneWinnerAndReplayCannotKillWinner(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	service := newTestAuthServiceAt(t, dataDir)
	original, err := service.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	type result struct {
		pair *TokenPair
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			pair, err := service.Refresh(context.Background(), original.RefreshToken)
			results <- result{pair: pair, err: err}
		}()
	}
	ready.Wait()
	close(start)

	var winner *TokenPair
	for range 2 {
		current := <-results
		if current.err == nil {
			if current.pair == nil || winner != nil {
				t.Fatalf("concurrent refresh returned multiple successful pairs")
			}
			winner = current.pair
			continue
		}
		if !errors.Is(current.err, ErrRefreshSuperseded) {
			t.Fatalf("concurrent refresh error = %v, want stale refresh rejection", current.err)
		}
	}
	if winner == nil {
		t.Fatal("concurrent refresh produced no winner")
	}
	if _, err := service.Refresh(context.Background(), original.RefreshToken); !errors.Is(err, ErrRefreshSuperseded) {
		t.Fatalf("replay after winning rotation = %v, want superseded", err)
	}
	for _, token := range []string{winner.AccessToken, winner.RefreshToken} {
		if _, err := service.ValidateToken(token); err != nil {
			t.Fatalf("replay terminated winning session: %v", err)
		}
	}

	restarted := newTestAuthServiceAt(t, dataDir)
	if _, err := restarted.ValidateRefreshToken(winner.RefreshToken); err != nil {
		t.Fatalf("winning refresh after restart: %v", err)
	}
}

func TestAuthSessionsStoreUsesPrivatePermissions(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	_ = newTestAuthServiceAt(t, dataDir)

	directoryInfo, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("stat auth data directory: %v", err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("auth data directory permissions = %04o, want 0700", got)
	}
	storeInfo, err := os.Stat(filepath.Join(dataDir, config.AuthSessionsFileName))
	if err != nil {
		t.Fatalf("stat auth session store: %v", err)
	}
	if got := storeInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("auth session store permissions = %04o, want 0600", got)
	}
}

func TestAuthServiceRejectsInvalidSessionStores(t *testing.T) {
	validHash := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		content string
	}{
		{name: "malformed JSON", content: `{"version":`},
		{name: "missing version", content: `{"sessions":{}}`},
		{name: "future version", content: `{"version":2,"sessions":{}}`},
		{name: "missing sessions map", content: `{"version":1}`},
		{name: "null sessions map", content: `{"version":1,"sessions":null}`},
		{name: "legacy revocation schema", content: `{"version":1,"revokedRefresh":{},"revokedAccess":{}}`},
		{name: "unknown field", content: `{"version":1,"sessions":{},"other":true}`},
		{name: "trailing JSON", content: `{"version":1,"sessions":{}} {}`},
		{name: "invalid session ID", content: `{"version":1,"sessions":{"not-a-uuid":{"username":"admin","refreshHash":"` + validHash + `","expiresAt":"9999-12-31T23:59:59Z"}}}`},
		{name: "invalid username", content: `{"version":1,"sessions":{"a88b7c22-6ddd-4f3d-8b61-4f1368dca9f1":{"username":" ","refreshHash":"` + validHash + `","expiresAt":"9999-12-31T23:59:59Z"}}}`},
		{name: "missing username", content: `{"version":1,"sessions":{"a88b7c22-6ddd-4f3d-8b61-4f1368dca9f1":{"refreshHash":"` + validHash + `","expiresAt":"9999-12-31T23:59:59Z"}}}`},
		{name: "missing refresh hash", content: `{"version":1,"sessions":{"a88b7c22-6ddd-4f3d-8b61-4f1368dca9f1":{"username":"admin","expiresAt":"9999-12-31T23:59:59Z"}}}`},
		{name: "missing expiration", content: `{"version":1,"sessions":{"a88b7c22-6ddd-4f3d-8b61-4f1368dca9f1":{"username":"admin","refreshHash":"` + validHash + `"}}}`},
		{name: "invalid refresh hash", content: `{"version":1,"sessions":{"a88b7c22-6ddd-4f3d-8b61-4f1368dca9f1":{"username":"admin","refreshHash":"invalid","expiresAt":"9999-12-31T23:59:59Z"}}}`},
		{name: "uppercase refresh hash", content: `{"version":1,"sessions":{"a88b7c22-6ddd-4f3d-8b61-4f1368dca9f1":{"username":"admin","refreshHash":"` + strings.Repeat("A", 64) + `","expiresAt":"9999-12-31T23:59:59Z"}}}`},
		{name: "invalid expiration", content: `{"version":1,"sessions":{"a88b7c22-6ddd-4f3d-8b61-4f1368dca9f1":{"username":"admin","refreshHash":"` + validHash + `","expiresAt":"0001-01-01T00:00:00Z"}}}`},
		{name: "null record", content: `{"version":1,"sessions":{"a88b7c22-6ddd-4f3d-8b61-4f1368dca9f1":null}}`},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data")
			_ = newTestAuthServiceAt(t, dataDir)
			storePath := filepath.Join(dataDir, config.AuthSessionsFileName)
			if err := os.WriteFile(storePath, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("replace session store: %v", err)
			}
			if _, err := NewAuthService(filesystem.NewOsFS(), testAuthConfig(t, dataDir)); err == nil {
				t.Fatal("constructor accepted an invalid session store")
			}
		})
	}
}

func TestAuthServiceRejectsNonregularAndSymlinkSessionStores(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		dataDir := filepath.Join(t.TempDir(), "data")
		_ = newTestAuthServiceAt(t, dataDir)
		storePath := filepath.Join(dataDir, config.AuthSessionsFileName)
		if err := os.Remove(storePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(storePath, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := NewAuthService(filesystem.NewOsFS(), testAuthConfig(t, dataDir)); err == nil {
			t.Fatal("constructor accepted a directory as the session store")
		}
	})

	for _, targetExists := range []bool{true, false} {
		name := "dangling symlink"
		if targetExists {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data")
			_ = newTestAuthServiceAt(t, dataDir)
			storePath := filepath.Join(dataDir, config.AuthSessionsFileName)
			if err := os.Remove(storePath); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target.json")
			if targetExists {
				if err := os.WriteFile(target, []byte(`{"version":1,"sessions":{}}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, storePath); err != nil {
				t.Fatalf("create symlink: %v", err)
			}
			if _, err := NewAuthService(filesystem.NewOsFS(), testAuthConfig(t, dataDir)); err == nil {
				t.Fatal("constructor accepted a symlink as the session store")
			}
		})
	}
}

func TestAuthServiceRejectsUnreadableSessionStore(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	_ = newTestAuthServiceAt(t, dataDir)
	storePath := filepath.Join(dataDir, config.AuthSessionsFileName)
	fsys := unreadableAuthStoreFS{FS: filesystem.NewOsFS(), path: storePath}
	if _, err := NewAuthService(fsys, testAuthConfig(t, dataDir)); err == nil {
		t.Fatal("constructor accepted an unreadable session store")
	}
}

func TestAuthServicePropagatesSessionStoreInspectionFailure(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	_ = newTestAuthServiceAt(t, dataDir)
	storePath := filepath.Join(dataDir, config.AuthSessionsFileName)
	if err := os.Remove(storePath); err != nil {
		t.Fatalf("remove session store: %v", err)
	}

	fsys := uninspectableAuthStoreFS{FS: filesystem.NewOsFS(), path: storePath}
	service, err := NewAuthService(fsys, testAuthConfig(t, dataDir))
	if service != nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("service=%t error=%v, want propagated store inspection failure", service != nil, err)
	}
	if _, err := os.Lstat(storePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection failure initialized a new store: %v", err)
	}
}

type uninspectableAuthStoreFS struct {
	filesystem.FS
	path string
}

func (fsys uninspectableAuthStoreFS) Lstat(name string) (fs.FileInfo, error) {
	if filepath.Clean(name) == fsys.path {
		return nil, fs.ErrPermission
	}
	return fsys.FS.Lstat(name)
}

func TestSessionPersistenceFailureTransactions(t *testing.T) {
	prepublication := []authPersistenceFailureStage{
		authPersistenceFailCreate,
		authPersistenceFailChmod,
		authPersistenceFailWrite,
		authPersistenceFailFileSync,
		authPersistenceFailFileClose,
		authPersistenceFailRename,
	}
	postpublication := []authPersistenceFailureStage{
		authPersistenceFailDirectoryOpen,
		authPersistenceFailDirectorySync,
		authPersistenceFailDirectoryClose,
	}
	for _, stage := range prepublication {
		for _, operation := range []string{"login", "refresh", "logout"} {
			t.Run(string(stage)+"/"+operation, func(t *testing.T) {
				exerciseSessionPersistenceFailure(t, stage, operation, false)
			})
		}
	}
	for _, stage := range postpublication {
		for _, operation := range []string{"login", "refresh", "logout"} {
			t.Run(string(stage)+"/"+operation, func(t *testing.T) {
				exerciseSessionPersistenceFailure(t, stage, operation, true)
			})
		}
	}
}

func exerciseSessionPersistenceFailure(t *testing.T, stage authPersistenceFailureStage, operation string, published bool) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "data")
	service, faultFS := newFaultInjectedAuthService(t, dataDir)
	var current *TokenPair
	var independent *TokenPair
	if operation != "login" {
		var err error
		current, err = service.Login(context.Background(), "admin", "correct-password")
		if err != nil {
			t.Fatalf("initial login: %v", err)
		}
		if operation == "logout" {
			independent, err = service.Login(context.Background(), "admin", "correct-password")
			if err != nil {
				t.Fatalf("independent login: %v", err)
			}
		}
	}

	faultFS.stage = stage
	var pair *TokenPair
	var persistErr error
	switch operation {
	case "login":
		pair, persistErr = service.Login(context.Background(), "admin", "correct-password")
	case "refresh":
		pair, persistErr = service.Refresh(context.Background(), current.RefreshToken)
	case "logout":
		persistErr = service.Logout(context.Background(), current.RefreshToken)
	}
	if pair != nil {
		t.Fatal("failed persistence operation returned credentials")
	}
	if !errors.Is(persistErr, errInjectedAuthPersistenceFailure) {
		t.Fatalf("persistence error = %v, want injected failure", persistErr)
	}
	if published != errors.Is(persistErr, ErrSessionRecoveryRequired) {
		t.Fatalf("terminal recovery classification = %t, want published=%t: %v", errors.Is(persistErr, ErrSessionRecoveryRequired), published, persistErr)
	}

	faultFS.stage = authPersistenceNoFailure
	restarted := newTestAuthServiceAt(t, dataDir)
	if operation == "login" {
		if published {
			if len(service.sessions) != 1 || len(restarted.sessions) != 1 {
				t.Fatalf("published failed login session counts = %d/%d, want retained in both processes", len(service.sessions), len(restarted.sessions))
			}
		} else if len(service.sessions) != 0 || len(restarted.sessions) != 0 {
			t.Fatalf("prepublication failed login left session counts = %d/%d, want empty", len(service.sessions), len(restarted.sessions))
		}
		if _, err := service.Login(context.Background(), "admin", "correct-password"); err != nil {
			t.Fatalf("login retry after persistence failure: %v", err)
		}
		return
	}

	if operation == "refresh" {
		if published {
			for _, currentService := range []*authService{service, restarted} {
				if _, err := currentService.ValidateRefreshToken(current.RefreshToken); !errors.Is(err, ErrRefreshSuperseded) {
					t.Fatalf("old refresh after published failure = %v, want rotated", err)
				}
				if _, err := currentService.ValidateAccessToken(current.AccessToken); err != nil {
					t.Fatalf("active session lost access after published refresh failure: %v", err)
				}
			}
			if _, err := service.Refresh(context.Background(), current.RefreshToken); !errors.Is(err, ErrRefreshSuperseded) {
				t.Fatalf("replay after published refresh failure = %v, want superseded", err)
			}
		} else {
			for _, currentService := range []*authService{service, restarted} {
				if _, err := currentService.ValidateRefreshToken(current.RefreshToken); err != nil {
					t.Fatalf("old refresh after prepublication failure: %v", err)
				}
				if _, err := currentService.ValidateAccessToken(current.AccessToken); err != nil {
					t.Fatalf("access after prepublication failure: %v", err)
				}
			}
			if replacement, err := service.Refresh(context.Background(), current.RefreshToken); err != nil || replacement == nil {
				t.Fatalf("refresh retry returned credentials=%t, error=%v", replacement != nil, err)
			}
		}
		return
	}

	if published {
		for _, currentService := range []*authService{service, restarted} {
			for _, token := range []string{current.AccessToken, current.RefreshToken} {
				if _, err := currentService.ValidateToken(token); !errors.Is(err, ErrTokenRevoked) {
					t.Fatalf("credential after published logout failure = %v, want inactive", err)
				}
			}
			if _, err := currentService.ValidateToken(independent.AccessToken); err != nil {
				t.Fatalf("published logout affected independent session: %v", err)
			}
		}
	} else {
		for _, currentService := range []*authService{service, restarted} {
			if _, err := currentService.ValidateRefreshToken(current.RefreshToken); err != nil {
				t.Fatalf("refresh after prepublication logout failure: %v", err)
			}
			if _, err := currentService.ValidateAccessToken(current.AccessToken); err != nil {
				t.Fatalf("access after prepublication logout failure: %v", err)
			}
		}
		if err := service.Logout(context.Background(), current.RefreshToken); err != nil {
			t.Fatalf("logout retry: %v", err)
		}
		if _, err := service.ValidateAccessToken(independent.AccessToken); err != nil {
			t.Fatalf("retry logout affected independent session: %v", err)
		}
	}
}

func TestValidationWaitsForPrepublicationRollback(t *testing.T) {
	service, faultFS := newFaultInjectedAuthService(t, filepath.Join(t.TempDir(), "data"))
	original, err := service.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	enteredSync := make(chan struct{})
	releaseSync := make(chan struct{})
	faultFS.stage = authPersistenceFailFileSync
	faultFS.syncEntered = enteredSync
	faultFS.syncRelease = releaseSync
	refreshResult := make(chan error, 1)
	go func() {
		pair, err := service.Refresh(context.Background(), original.RefreshToken)
		if pair != nil {
			refreshResult <- errors.New("failed refresh returned credentials")
			return
		}
		refreshResult <- err
	}()
	select {
	case <-enteredSync:
	case <-time.After(5 * time.Second):
		close(releaseSync)
		t.Fatal("refresh did not reach injected file sync")
	}

	validationStarted := make(chan struct{})
	validationResult := make(chan error, 1)
	go func() {
		close(validationStarted)
		_, err := service.ValidateRefreshToken(original.RefreshToken)
		validationResult <- err
	}()
	<-validationStarted
	select {
	case err := <-validationResult:
		close(releaseSync)
		<-refreshResult
		t.Fatalf("validation completed before persistence rollback: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(releaseSync)
	if err := <-refreshResult; !errors.Is(err, errInjectedAuthPersistenceFailure) {
		t.Fatalf("refresh failure = %v, want injected file sync failure", err)
	}
	if err := <-validationResult; err != nil {
		t.Fatalf("validation after rollback = %v, want current refresh accepted", err)
	}
}

func TestAuthServiceRejectsUndurableNewSessionDirectory(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "new-parent")
	dataDir := filepath.Join(parent, "data")
	fsys := failingAuthDirectorySyncFS{FS: filesystem.NewOsFS(), path: parent}
	for attempt := range 2 {
		svc, err := NewAuthService(fsys, testAuthConfig(t, dataDir))
		if svc != nil || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("startup attempt %d with undurable directory returned service=%t, error=%v", attempt, svc != nil, err)
		}
	}
}

type failingAuthDirectorySyncFS struct {
	filesystem.FS
	path string
}

func (fsys failingAuthDirectorySyncFS) Open(name string) (afero.File, error) {
	file, err := fsys.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(name) == fsys.path {
		return failingAuthDirectorySyncFile{File: file}, nil
	}
	return file, nil
}

type failingAuthDirectorySyncFile struct {
	afero.File
}

func (file failingAuthDirectorySyncFile) Sync() error {
	return fs.ErrPermission
}

type unreadableAuthStoreFS struct {
	filesystem.FS
	path string
}

func (fsys unreadableAuthStoreFS) Open(name string) (afero.File, error) {
	if filepath.Clean(name) == fsys.path {
		return nil, fs.ErrPermission
	}
	return fsys.FS.Open(name)
}

type authPersistenceFailureStage string

const (
	authPersistenceNoFailure          authPersistenceFailureStage = ""
	authPersistenceFailCreate         authPersistenceFailureStage = "create"
	authPersistenceFailChmod          authPersistenceFailureStage = "chmod"
	authPersistenceFailWrite          authPersistenceFailureStage = "write"
	authPersistenceFailFileSync       authPersistenceFailureStage = "file-sync"
	authPersistenceFailFileClose      authPersistenceFailureStage = "file-close"
	authPersistenceFailRename         authPersistenceFailureStage = "rename"
	authPersistenceFailDirectoryOpen  authPersistenceFailureStage = "directory-open"
	authPersistenceFailDirectorySync  authPersistenceFailureStage = "directory-sync"
	authPersistenceFailDirectoryClose authPersistenceFailureStage = "directory-close"
)

var errInjectedAuthPersistenceFailure = errors.New("injected auth persistence failure")

type authPersistenceFaultFS struct {
	filesystem.FS
	storePath   string
	stage       authPersistenceFailureStage
	syncEntered chan struct{}
	syncRelease chan struct{}
	syncOnce    sync.Once
}

func newFaultInjectedAuthService(t *testing.T, dataDir string) (*authService, *authPersistenceFaultFS) {
	t.Helper()
	fsys := &authPersistenceFaultFS{
		FS:        filesystem.NewOsFS(),
		storePath: filepath.Join(dataDir, config.AuthSessionsFileName),
	}
	svc, err := NewAuthService(fsys, testAuthConfig(t, dataDir))
	if err != nil {
		t.Fatalf("create auth service: %v", err)
	}
	auth, ok := svc.(*authService)
	if !ok {
		t.Fatal("auth service has an unexpected implementation")
	}
	return auth, fsys
}

func (fsys *authPersistenceFaultFS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	temporary := isAuthSessionTemporary(name, fsys.storePath)
	if temporary && fsys.stage == authPersistenceFailCreate {
		return nil, errInjectedAuthPersistenceFailure
	}
	file, err := fsys.FS.OpenFile(name, flag, perm)
	if err != nil || !temporary {
		return file, err
	}
	return authPersistenceFaultFile{File: file, fsys: fsys, temporary: true}, nil
}

func (fsys *authPersistenceFaultFS) Chmod(name string, mode os.FileMode) error {
	if isAuthSessionTemporary(name, fsys.storePath) && fsys.stage == authPersistenceFailChmod {
		return errInjectedAuthPersistenceFailure
	}
	return fsys.FS.Chmod(name, mode)
}

func (fsys *authPersistenceFaultFS) Rename(oldpath, newpath string) error {
	if isAuthSessionTemporary(oldpath, fsys.storePath) &&
		filepath.Clean(newpath) == filepath.Clean(fsys.storePath) &&
		fsys.stage == authPersistenceFailRename {
		return errInjectedAuthPersistenceFailure
	}
	return fsys.FS.Rename(oldpath, newpath)
}

func (fsys *authPersistenceFaultFS) Open(name string) (afero.File, error) {
	directory := filepath.Clean(name) == filepath.Clean(filepath.Dir(fsys.storePath))
	if directory && fsys.stage == authPersistenceFailDirectoryOpen {
		return nil, errInjectedAuthPersistenceFailure
	}
	file, err := fsys.FS.Open(name)
	if err != nil || !directory {
		return file, err
	}
	return authPersistenceFaultFile{File: file, fsys: fsys, directory: true}, nil
}

func isAuthSessionTemporary(path, storePath string) bool {
	return filepath.Dir(filepath.Clean(path)) == filepath.Dir(filepath.Clean(storePath)) &&
		strings.HasPrefix(filepath.Base(path), filepath.Base(storePath)+".tmp.")
}

type authPersistenceFaultFile struct {
	afero.File
	fsys      *authPersistenceFaultFS
	temporary bool
	directory bool
}

func (file authPersistenceFaultFile) Write(data []byte) (int, error) {
	if file.temporary && file.fsys.stage == authPersistenceFailWrite {
		return 0, errInjectedAuthPersistenceFailure
	}
	return file.File.Write(data)
}

func (file authPersistenceFaultFile) Sync() error {
	if file.temporary && file.fsys.stage == authPersistenceFailFileSync {
		if file.fsys.syncEntered != nil && file.fsys.syncRelease != nil {
			file.fsys.syncOnce.Do(func() {
				close(file.fsys.syncEntered)
				<-file.fsys.syncRelease
			})
		}
		return errInjectedAuthPersistenceFailure
	}
	if file.directory && file.fsys.stage == authPersistenceFailDirectorySync {
		return errInjectedAuthPersistenceFailure
	}
	return file.File.Sync()
}

func (file authPersistenceFaultFile) Close() error {
	err := file.File.Close()
	if file.temporary && file.fsys.stage == authPersistenceFailFileClose ||
		file.directory && file.fsys.stage == authPersistenceFailDirectoryClose {
		return errors.Join(err, errInjectedAuthPersistenceFailure)
	}
	return err
}
