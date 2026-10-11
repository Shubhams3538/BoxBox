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

func TestAuthPrepublicationPersistenceFailuresAreRetryable(t *testing.T) {
	stages := []authPersistenceFailureStage{
		authPersistenceFailCreate,
		authPersistenceFailChmod,
		authPersistenceFailWrite,
		authPersistenceFailFileSync,
		authPersistenceFailFileClose,
		authPersistenceFailRename,
	}
	for _, stage := range stages {
		for _, operation := range []string{"refresh", "logout"} {
			t.Run(string(stage)+"/"+operation, func(t *testing.T) {
				dataDir := filepath.Join(t.TempDir(), "data")
				service, faultFS := newFaultInjectedAuthService(t, dataDir)
				pair, err := service.Login(context.Background(), "admin", "correct-password")
				if err != nil {
					t.Fatalf("login: %v", err)
				}

				faultFS.stage = stage
				var persistErr error
				if operation == "refresh" {
					replacement, err := service.Refresh(context.Background(), pair.RefreshToken)
					persistErr = err
					if replacement != nil {
						t.Fatal("failed refresh returned credentials")
					}
				} else {
					persistErr = service.Logout(context.Background(), pair.RefreshToken, pair.AccessToken)
				}
				if !errors.Is(persistErr, errInjectedAuthPersistenceFailure) {
					t.Fatalf("persistence error = %v, want injected failure", persistErr)
				}
				if errors.Is(persistErr, ErrSessionRecoveryRequired) {
					t.Fatalf("pre-publication error marked terminal: %v", persistErr)
				}

				faultFS.stage = authPersistenceNoFailure
				restarted := newTestAuthServiceAt(t, dataDir)
				for _, current := range []*authService{service, restarted} {
					if _, err := current.ValidateRefreshToken(pair.RefreshToken); err != nil {
						t.Fatalf("refresh token after failed %s in process/restart: %v", operation, err)
					}
					if operation == "logout" {
						if _, err := current.ValidateAccessToken(pair.AccessToken); err != nil {
							t.Fatalf("access token after failed logout in process/restart: %v", err)
						}
					}
				}

				if operation == "refresh" {
					replacement, err := service.Refresh(context.Background(), pair.RefreshToken)
					if err != nil || replacement == nil {
						t.Fatalf("retry refresh returned credentials=%t, error=%v", replacement != nil, err)
					}
				} else if err := service.Logout(context.Background(), pair.RefreshToken, pair.AccessToken); err != nil {
					t.Fatalf("retry logout: %v", err)
				}
				if _, err := service.ValidateRefreshToken(pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
					t.Fatalf("refresh token after retry = %v, want revoked", err)
				}
				if operation == "logout" {
					if _, err := service.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
						t.Fatalf("access token after retry = %v, want revoked", err)
					}
				}
			})
		}
	}
}

func TestAuthPostpublicationPersistenceFailuresRequireRecovery(t *testing.T) {
	stages := []authPersistenceFailureStage{
		authPersistenceFailDirectoryOpen,
		authPersistenceFailDirectorySync,
		authPersistenceFailDirectoryClose,
	}
	for _, stage := range stages {
		for _, operation := range []string{"refresh", "logout"} {
			t.Run(string(stage)+"/"+operation, func(t *testing.T) {
				dataDir := filepath.Join(t.TempDir(), "data")
				service, faultFS := newFaultInjectedAuthService(t, dataDir)
				pair, err := service.Login(context.Background(), "admin", "correct-password")
				if err != nil {
					t.Fatalf("login: %v", err)
				}
				active, err := service.Login(context.Background(), "admin", "correct-password")
				if err != nil {
					t.Fatalf("login for active tokens: %v", err)
				}

				faultFS.stage = stage
				var persistErr error
				if operation == "refresh" {
					replacement, err := service.Refresh(context.Background(), pair.RefreshToken)
					persistErr = err
					if replacement != nil {
						t.Fatal("failed refresh returned credentials")
					}
				} else {
					persistErr = service.Logout(context.Background(), pair.RefreshToken, pair.AccessToken)
				}
				if !errors.Is(persistErr, ErrSessionRecoveryRequired) {
					t.Fatalf("post-publication error = %v, want session recovery required", persistErr)
				}
				if !errors.Is(persistErr, errInjectedAuthPersistenceFailure) {
					t.Fatalf("post-publication error lost persistence cause: %v", persistErr)
				}

				faultFS.stage = authPersistenceNoFailure
				restarted := newTestAuthServiceAt(t, dataDir)
				for _, current := range []*authService{service, restarted} {
					if _, err := current.ValidateRefreshToken(pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
						t.Fatalf("old refresh token after failed %s in process/restart = %v, want revoked", operation, err)
					}
					if operation == "logout" {
						if _, err := current.ValidateAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
							t.Fatalf("access token after failed logout in process/restart = %v, want revoked", err)
						}
					}
					if _, err := current.ValidateRefreshToken(active.RefreshToken); err != nil {
						t.Fatalf("unaffected refresh token in process/restart: %v", err)
					}
				}
			})
		}
	}
}

func TestFailedMixedLogoutPreservesPreviouslyCommittedAccessRevocation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	service, faultFS := newFaultInjectedAuthService(t, dataDir)
	revokedAccessPair, err := service.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login for access token: %v", err)
	}
	firstRefresh, err := service.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login for initial logout: %v", err)
	}
	retryRefresh, err := service.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("login for retryable logout: %v", err)
	}
	if err := service.Logout(context.Background(), firstRefresh.RefreshToken, revokedAccessPair.AccessToken); err != nil {
		t.Fatalf("commit initial mixed logout: %v", err)
	}
	if _, err := service.ValidateAccessToken(revokedAccessPair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("access token after initial logout = %v, want revoked", err)
	}

	faultFS.stage = authPersistenceFailWrite
	err = service.Logout(context.Background(), retryRefresh.RefreshToken, revokedAccessPair.AccessToken)
	if !errors.Is(err, errInjectedAuthPersistenceFailure) {
		t.Fatalf("failed mixed logout error = %v, want injected failure", err)
	}
	if errors.Is(err, ErrSessionRecoveryRequired) {
		t.Fatalf("pre-publication mixed logout error marked terminal: %v", err)
	}
	if _, err := service.ValidateRefreshToken(retryRefresh.RefreshToken); err != nil {
		t.Fatalf("retry refresh token after failed mixed logout: %v", err)
	}
	if _, err := service.ValidateAccessToken(revokedAccessPair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("previously revoked access token after failed logout = %v, want revoked", err)
	}

	faultFS.stage = authPersistenceNoFailure
	if err := service.Logout(context.Background(), retryRefresh.RefreshToken, revokedAccessPair.AccessToken); err != nil {
		t.Fatalf("retry mixed logout: %v", err)
	}
	restarted := newTestAuthServiceAt(t, dataDir)
	if _, err := restarted.ValidateRefreshToken(retryRefresh.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("retried refresh token after restart = %v, want revoked", err)
	}
	if _, err := restarted.ValidateAccessToken(revokedAccessPair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("previously revoked access token after restart = %v, want revoked", err)
	}
}

func TestRefreshValidationWaitsForPrepublicationRollback(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	service, faultFS := newFaultInjectedAuthService(t, dataDir)
	pair, err := service.Login(context.Background(), "admin", "correct-password")
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
		replacement, err := service.Refresh(context.Background(), pair.RefreshToken)
		if replacement != nil {
			refreshResult <- errors.New("failed refresh returned credentials")
			return
		}
		refreshResult <- err
	}()
	select {
	case <-enteredSync:
	case <-time.After(5 * time.Second):
		close(releaseSync)
		t.Fatal("refresh did not reach the injected sync failure")
	}

	validationStarted := make(chan struct{})
	validationResult := make(chan error, 1)
	go func() {
		close(validationStarted)
		_, err := service.ValidateRefreshToken(pair.RefreshToken)
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
		t.Fatalf("refresh failure = %v, want injected sync failure", err)
	}
	if err := <-validationResult; err != nil {
		t.Fatalf("validation after rollback = %v, want valid token", err)
	}
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
		storePath: filepath.Join(dataDir, config.AuthRevocationsFileName),
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
	temporary := isAuthRevocationTemporary(name, fsys.storePath)
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
	if isAuthRevocationTemporary(name, fsys.storePath) && fsys.stage == authPersistenceFailChmod {
		return errInjectedAuthPersistenceFailure
	}
	return fsys.FS.Chmod(name, mode)
}

func (fsys *authPersistenceFaultFS) Rename(oldpath, newpath string) error {
	if isAuthRevocationTemporary(oldpath, fsys.storePath) &&
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

func isAuthRevocationTemporary(path, storePath string) bool {
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

func testAuthConfig(t *testing.T, dataDir string) AuthServiceConfig {
	t.Helper()
	return AuthServiceConfig{
		DataDir:   dataDir,
		JWTSecret: "test-secret",
		Users:     map[string]string{"admin": testPasswordHash(t, "correct-password")},
	}
}
