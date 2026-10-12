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

const authSessionsVersion = 1

type sessionRecord struct {
	Username    string    `json:"username"`
	RefreshHash string    `json:"refreshHash"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type authSessionsSnapshot struct {
	Version  int                      `json:"version"`
	Sessions map[string]sessionRecord `json:"sessions"`
}

func sessionRefreshHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *authService) loadSessions() error {
	if err := s.prepareSessionsDirectory(); err != nil {
		return fmt.Errorf("prepare auth session directory: %w", err)
	}

	info, err := s.fs.Lstat(s.sessionsPath)
	if errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, err := s.persistSessionsLocked()
		return err
	}
	if err != nil {
		return fmt.Errorf("inspect auth session store: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("auth session store is not a regular file")
	}
	if err := s.fs.Chmod(s.sessionsPath, 0o600); err != nil {
		return fmt.Errorf("secure auth session store: %w", err)
	}

	file, err := s.fs.Open(s.sessionsPath)
	if err != nil {
		return fmt.Errorf("open auth session store: %w", err)
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var snapshot authSessionsSnapshot
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
		return fmt.Errorf("decode auth session store: %w", decodeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close auth session store: %w", closeErr)
	}
	if snapshot.Version != authSessionsVersion {
		return fmt.Errorf("unsupported auth session store version %d", snapshot.Version)
	}
	if snapshot.Sessions == nil {
		return errors.New("auth session store is missing required sessions map")
	}
	if err := validateSessionEntries(snapshot.Sessions); err != nil {
		return err
	}

	s.sessions = snapshot.Sessions
	return nil
}

func validateSessionEntries(sessions map[string]sessionRecord) error {
	for sessionID, record := range sessions {
		if !validUUID(sessionID) {
			return errors.New("auth session store contains an invalid session ID")
		}
		if strings.TrimSpace(record.Username) == "" {
			return errors.New("auth session store contains an invalid username")
		}
		if len(record.RefreshHash) != sha256.Size*2 {
			return errors.New("auth session store contains an invalid refresh hash")
		}
		decoded, err := hex.DecodeString(record.RefreshHash)
		if err != nil || hex.EncodeToString(decoded) != record.RefreshHash {
			return errors.New("auth session store contains an invalid refresh hash")
		}
		if record.ExpiresAt.IsZero() {
			return errors.New("auth session store contains an invalid expiration")
		}
	}
	return nil
}

func (s *authService) prepareSessionsDirectory() (err error) {
	directory := filepath.Dir(s.sessionsPath)
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

type authSessionWriteResult struct {
	published bool
}

// persistSessionsLocked writes a complete snapshot while the service mutex is held.
func (s *authService) persistSessionsLocked() (authSessionWriteResult, error) {
	var result authSessionWriteResult
	temporary := s.sessionsPath + ".tmp." + uuid.New().String()
	file, err := s.fs.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result, fmt.Errorf("create temporary auth session store: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !result.published {
			_ = s.fs.Remove(temporary)
		}
	}()

	if err := s.fs.Chmod(temporary, 0o600); err != nil {
		return result, fmt.Errorf("secure temporary auth session store: %w", err)
	}
	snapshot := authSessionsSnapshot{Version: authSessionsVersion, Sessions: s.sessions}
	if err := json.NewEncoder(file).Encode(snapshot); err != nil {
		return result, fmt.Errorf("encode auth session store: %w", err)
	}
	if err := file.Sync(); err != nil {
		return result, fmt.Errorf("sync auth session store: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return result, fmt.Errorf("close auth session store: %w", err)
	}
	closed = true
	if err := s.fs.Rename(temporary, s.sessionsPath); err != nil {
		return result, fmt.Errorf("publish auth session store: %w", err)
	}
	result.published = true
	if err := syncDirectory(s.fs, filepath.Dir(s.sessionsPath)); err != nil {
		return result, fmt.Errorf("sync auth session directory: %w", err)
	}
	return result, nil
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
