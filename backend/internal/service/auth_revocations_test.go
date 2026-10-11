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

	"github.com/jR4dh3y/BoxBox/backend/internal/config"
	"github.com/jR4dh3y/BoxBox/backend/internal/pkg/filesystem"
	"github.com/spf13/afero"
)

func TestLogoutRevocationsPersistAcrossRestart(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := newTestAuthServiceAt(t, dataDir)

	revoked, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login before logout: %v", err)
	}
	active, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login for active tokens: %v", err)
	}
	if err := first.Logout(context.Background(), revoked.RefreshToken, revoked.AccessToken); err != nil {
		t.Fatalf("logout: %v", err)
	}

	second := newTestAuthServiceAt(t, dataDir)
	if _, err := second.ValidateRefreshToken(revoked.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("refresh token after restart = %v, want revoked", err)
	}
	if _, err := second.ValidateAccessToken(revoked.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("access token after restart = %v, want revoked", err)
	}
	if _, err := second.ValidateRefreshToken(active.RefreshToken); err != nil {
		t.Fatalf("unrevoked refresh token after restart: %v", err)
	}
	if _, err := second.ValidateAccessToken(active.AccessToken); err != nil {
		t.Fatalf("unrevoked access token after restart: %v", err)
	}

	store, err := os.ReadFile(filepath.Join(dataDir, config.AuthRevocationsFileName))
	if err != nil {
		t.Fatalf("read revocation store: %v", err)
	}
	if strings.Contains(string(store), revoked.RefreshToken) || strings.Contains(string(store), revoked.AccessToken) {
		t.Fatal("revocation store contains a raw JWT")
	}
}

func TestAuthRevocationStoreUsesPrivatePermissions(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	_ = newTestAuthServiceAt(t, dataDir)

	directoryInfo, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("stat auth data directory: %v", err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("auth data directory permissions = %04o, want 0700", got)
	}
	storeInfo, err := os.Stat(filepath.Join(dataDir, config.AuthRevocationsFileName))
	if err != nil {
		t.Fatalf("stat auth revocation store: %v", err)
	}
	if got := storeInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("auth revocation store permissions = %04o, want 0600", got)
	}
}

func TestRefreshRotationRevocationsPersistAcrossRestart(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := newTestAuthServiceAt(t, dataDir)
	original, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	replacement, err := first.Refresh(context.Background(), original.RefreshToken)
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}

	second := newTestAuthServiceAt(t, dataDir)
	if _, err := second.Refresh(context.Background(), original.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("rotated refresh token after restart = %v, want revoked", err)
	}
	if _, err := second.ValidateRefreshToken(replacement.RefreshToken); err != nil {
		t.Fatalf("replacement refresh token after restart: %v", err)
	}
	if _, err := second.ValidateAccessToken(replacement.AccessToken); err != nil {
		t.Fatalf("replacement access token after restart: %v", err)
	}
	if _, err := second.Refresh(context.Background(), replacement.RefreshToken); err != nil {
		t.Fatalf("use replacement refresh token after restart: %v", err)
	}
}

func TestAuthServiceRejectsInvalidRevocationStores(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{name: "malformed JSON", content: `{"version":`},
		{name: "missing version", content: `{"revokedRefresh":{},"revokedAccess":{}}`},
		{name: "missing maps", content: `{"version":1,"revokedRefresh":{}}`},
		{name: "invalid refresh hash", content: `{"version":1,"revokedRefresh":{"not-hex":"9999-12-31T23:59:59Z"},"revokedAccess":{}}`},
		{name: "invalid expiration", content: `{"version":1,"revokedRefresh":{},"revokedAccess":{"jti":"0001-01-01T00:00:00Z"}}`},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data")
			_ = newTestAuthServiceAt(t, dataDir)
			storePath := filepath.Join(dataDir, config.AuthRevocationsFileName)
			if err := os.WriteFile(storePath, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("corrupt revocation store: %v", err)
			}
			if _, err := NewAuthService(filesystem.NewOsFS(), testAuthConfig(t, dataDir)); err == nil {
				t.Fatal("constructor accepted an invalid revocation store")
			}
		})
	}
}

func TestAuthServiceRejectsUnreadableRevocationStore(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	_ = newTestAuthServiceAt(t, dataDir)
	storePath := filepath.Join(dataDir, config.AuthRevocationsFileName)
	fsys := unreadableAuthStoreFS{FS: filesystem.NewOsFS(), path: storePath}
	if _, err := NewAuthService(fsys, testAuthConfig(t, dataDir)); err == nil {
		t.Fatal("constructor accepted an unreadable revocation store")
	}
}

func TestAuthPersistenceFailureDoesNotReportLogoutOrRefreshSuccess(t *testing.T) {
	t.Run("refresh", func(t *testing.T) {
		dataDir := filepath.Join(t.TempDir(), "data")
		fsys := &failingAuthStoreWriteFS{FS: filesystem.NewOsFS()}
		service, err := NewAuthService(fsys, testAuthConfig(t, dataDir))
		if err != nil {
			t.Fatalf("create auth service: %v", err)
		}
		pair, err := service.Login(context.Background(), "admin", "correct-password")
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		fsys.fail = true
		replacement, err := service.Refresh(context.Background(), pair.RefreshToken)
		if err == nil || replacement != nil {
			t.Fatalf("refresh returned credentials=%t and error=%v", replacement != nil, err)
		}
		if _, err := service.ValidateRefreshToken(pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("refresh token after failed persistence = %v, want in-memory revocation", err)
		}
	})

	t.Run("logout", func(t *testing.T) {
		dataDir := filepath.Join(t.TempDir(), "data")
		fsys := &failingAuthStoreWriteFS{FS: filesystem.NewOsFS()}
		service, err := NewAuthService(fsys, testAuthConfig(t, dataDir))
		if err != nil {
			t.Fatalf("create auth service: %v", err)
		}
		pair, err := service.Login(context.Background(), "admin", "correct-password")
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		fsys.fail = true
		if err := service.Logout(context.Background(), pair.RefreshToken, pair.AccessToken); err == nil {
			t.Fatal("logout succeeded without committing revocations")
		}
		if _, err := service.ValidateRefreshToken(pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("refresh token after failed persistence = %v, want in-memory revocation", err)
		}
		if _, err := service.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("access token after failed persistence = %v, want in-memory revocation", err)
		}
	})
}

func TestConcurrentRefreshPersistsExactlyOneRotation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := newTestAuthServiceAt(t, dataDir)
	original, err := first.Login(context.Background(), "admin", "correct-password")
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
			pair, err := first.Refresh(context.Background(), original.RefreshToken)
			results <- result{pair: pair, err: err}
		}()
	}
	ready.Wait()
	close(start)

	var replacement *TokenPair
	revoked := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			if result.pair == nil || replacement != nil {
				t.Fatalf("successful refresh returned credentials=%t while another succeeded", result.pair != nil)
			}
			replacement = result.pair
			continue
		}
		if !errors.Is(result.err, ErrTokenRevoked) {
			t.Fatalf("concurrent refresh error = %v, want revoked", result.err)
		}
		revoked++
	}
	if replacement == nil || revoked != 1 {
		t.Fatalf("successful rotations = %t, rejected rotations = %d, want one each", replacement != nil, revoked)
	}

	second := newTestAuthServiceAt(t, dataDir)
	if _, err := second.ValidateRefreshToken(original.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("original refresh token after restart = %v, want revoked", err)
	}
	if _, err := second.ValidateRefreshToken(replacement.RefreshToken); err != nil {
		t.Fatalf("winning replacement after restart: %v", err)
	}
}

func TestExpiredCleanupPreservesUnexpiredRevocations(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := newTestAuthServiceAt(t, dataDir)
	revoked, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login for revocation: %v", err)
	}
	active, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login for active tokens: %v", err)
	}
	if err := first.Logout(context.Background(), revoked.RefreshToken, revoked.AccessToken); err != nil {
		t.Fatalf("logout: %v", err)
	}

	expiredRefreshHash := refreshTokenHash("expired refresh token")
	first.mu.Lock()
	first.revokedRefresh[expiredRefreshHash] = time.Now().Add(-time.Second)
	first.revokedAccess["expired-access-jti"] = time.Now().Add(-time.Second)
	first.mu.Unlock()
	if err := first.CleanupExpiredTokens(); err != nil {
		t.Fatalf("clean expired revocations: %v", err)
	}

	second := newTestAuthServiceAt(t, dataDir)
	if _, exists := second.revokedRefresh[expiredRefreshHash]; exists {
		t.Fatal("expired refresh revocation survived cleanup")
	}
	if _, exists := second.revokedAccess["expired-access-jti"]; exists {
		t.Fatal("expired access revocation survived cleanup")
	}
	if _, err := second.ValidateRefreshToken(revoked.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("unexpired refresh revocation after cleanup = %v, want revoked", err)
	}
	if _, err := second.ValidateAccessToken(revoked.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("unexpired access revocation after cleanup = %v, want revoked", err)
	}
	if _, err := second.ValidateRefreshToken(active.RefreshToken); err != nil {
		t.Fatalf("unrevoked refresh token after cleanup: %v", err)
	}
}

func TestAuthServiceRejectsUndurableNewDataDirectory(t *testing.T) {
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

func TestAuthRevocationsWorkWithUnreadableExistingAncestor(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fsys := unreadableAuthStoreFS{FS: filesystem.NewOsFS(), path: parent}
	cfg := testAuthConfig(t, dataDir)
	first, err := NewAuthService(fsys, cfg)
	if err != nil {
		t.Fatalf("startup beneath existing unreadable ancestor: %v", err)
	}
	pair, err := first.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Logout(context.Background(), pair.RefreshToken, pair.AccessToken); err != nil {
		t.Fatal(err)
	}
	second, err := NewAuthService(fsys, cfg)
	if err != nil {
		t.Fatalf("restart beneath existing unreadable ancestor: %v", err)
	}
	if _, err := second.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("access token after restart = %v, want revoked", err)
	}
	if _, err := second.Refresh(context.Background(), pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("refresh token after restart = %v, want revoked", err)
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

type failingAuthStoreWriteFS struct {
	filesystem.FS
	fail bool
}

func (fsys *failingAuthStoreWriteFS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if fsys.fail && strings.Contains(filepath.Base(name), ".tmp.") {
		return nil, errors.New("injected auth store write failure")
	}
	return fsys.FS.OpenFile(name, flag, perm)
}

func testAuthConfig(t *testing.T, dataDir string) AuthServiceConfig {
	t.Helper()
	return AuthServiceConfig{
		DataDir:   dataDir,
		JWTSecret: "test-secret",
		Users:     map[string]string{"admin": testPasswordHash(t, "correct-password")},
	}
}
