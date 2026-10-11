package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"uuid"

	"github.com/jR4dh3y/BoxBox/backend/internal/pkg/filesystem"
)

const authRevocationsVersion = 1

type authRevocationsSnapshot struct {
	Version        int                  `json:"version"`
	RevokedRefresh map[string]time.Time `json:"revokedRefresh"`
	RevokedAccess  map[string]time.Time `json:"revokedAccess"`
}

func refreshTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *authService) loadRevocations() error {
	if err := s.prepareRevocationDirectory(); err != nil {
		return fmt.Errorf("prepare auth revocation directory: %w", err)
	}

	exists, err := s.fs.Exists(s.revocationsPath)
	if err != nil {
		return fmt.Errorf("check auth revocation store: %w", err)
	}
	if !exists {
		s.mu.Lock()
		err := s.persistRevocationsLocked()
		s.mu.Unlock()
		return err
	}

	info, err := s.fs.Lstat(s.revocationsPath)
	if err != nil {
		return fmt.Errorf("inspect auth revocation store: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("auth revocation store is not a regular file")
	}
	if err := s.fs.Chmod(s.revocationsPath, 0o600); err != nil {
		return fmt.Errorf("secure auth revocation store: %w", err)
	}

	file, err := s.fs.Open(s.revocationsPath)
	if err != nil {
		return fmt.Errorf("open auth revocation store: %w", err)
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var snapshot authRevocationsSnapshot
	decodeErr := decoder.Decode(&snapshot)
	if decodeErr == nil {
		var trailing json.RawMessage
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			if err == nil {
				decodeErr = errors.New("trailing JSON data")
			} else {
				decodeErr = err
			}
		}
	}
	closeErr := file.Close()
	if decodeErr != nil {
		return fmt.Errorf("decode auth revocation store: %w", decodeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close auth revocation store: %w", closeErr)
	}
	if snapshot.Version != authRevocationsVersion {
		return fmt.Errorf("unsupported auth revocation store version %d", snapshot.Version)
	}
	if snapshot.RevokedRefresh == nil || snapshot.RevokedAccess == nil {
		return errors.New("auth revocation store is missing required maps")
	}
	if err := validateRevocationEntries(snapshot); err != nil {
		return err
	}

	s.revokedRefresh = snapshot.RevokedRefresh
	s.revokedAccess = snapshot.RevokedAccess
	return nil
}

func validateRevocationEntries(snapshot authRevocationsSnapshot) error {
	for hash, expiresAt := range snapshot.RevokedRefresh {
		if len(hash) != sha256.Size*2 {
			return errors.New("auth revocation store contains an invalid refresh hash")
		}
		decoded, err := hex.DecodeString(hash)
		if err != nil || hex.EncodeToString(decoded) != hash {
			return errors.New("auth revocation store contains an invalid refresh hash")
		}
		if expiresAt.IsZero() {
			return errors.New("auth revocation store contains an invalid refresh expiration")
		}
	}
	for id, expiresAt := range snapshot.RevokedAccess {
		if strings.TrimSpace(id) == "" || expiresAt.IsZero() {
			return errors.New("auth revocation store contains an invalid access revocation")
		}
	}
	return nil
}

func (s *authService) prepareRevocationDirectory() (err error) {
	directory := filepath.Dir(s.revocationsPath)
	existingAncestor := directory
	for {
		if _, err := s.fs.Stat(existingAncestor); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(existingAncestor)
		if parent == existingAncestor {
			return fmt.Errorf("auth storage has no existing ancestor: %s", directory)
		}
		existingAncestor = parent
	}
	createdLeaf := directory
	defer func() {
		if err == nil {
			return
		}
		// Leave no incomplete provisioning for a later startup to trust.
		for current := createdLeaf; current != existingAncestor; current = filepath.Dir(current) {
			if removeErr := s.fs.Remove(current); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
		}
	}()
	if err := s.fs.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := s.fs.Chmod(directory, 0o700); err != nil {
		return err
	}
	// Publish newly created directory entries up to the first existing parent.
	for {
		if err := syncDirectory(s.fs, directory); err != nil {
			return err
		}
		if directory == existingAncestor {
			return nil
		}
		directory = filepath.Dir(directory)
	}
}

// persistRevocationsLocked writes a snapshot while the service mutex is held.
func (s *authService) persistRevocationsLocked() error {
	temporary := s.revocationsPath + ".tmp." + uuid.New().String()
	file, err := s.fs.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary auth revocation store: %w", err)
	}
	closed := false
	renamed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !renamed {
			_ = s.fs.Remove(temporary)
		}
	}()

	if err := s.fs.Chmod(temporary, 0o600); err != nil {
		return fmt.Errorf("secure temporary auth revocation store: %w", err)
	}
	snapshot := authRevocationsSnapshot{
		Version:        authRevocationsVersion,
		RevokedRefresh: s.revokedRefresh,
		RevokedAccess:  s.revokedAccess,
	}
	if err := json.NewEncoder(file).Encode(snapshot); err != nil {
		return fmt.Errorf("encode auth revocation store: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync auth revocation store: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close auth revocation store: %w", err)
	}
	closed = true
	if err := s.fs.Rename(temporary, s.revocationsPath); err != nil {
		return fmt.Errorf("publish auth revocation store: %w", err)
	}
	renamed = true
	if err := syncDirectory(s.fs, filepath.Dir(s.revocationsPath)); err != nil {
		return fmt.Errorf("sync auth revocation directory: %w", err)
	}
	return nil
}

func syncDirectory(fsys filesystem.FS, path string) error {
	directory, err := fsys.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}
