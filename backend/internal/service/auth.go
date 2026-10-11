package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"path/filepath"
	"sync"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jR4dh3y/BoxBox/backend/internal/config"
	"github.com/jR4dh3y/BoxBox/backend/internal/pkg/filesystem"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// Auth-related errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenRevoked       = errors.New("token revoked")
)

type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// Claims represents the JWT claims for access tokens
type Claims struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

// TokenPair contains both access and refresh tokens
type TokenPair struct {
	AccessToken      string    `json:"accessToken"`
	RefreshToken     string    `json:"-"`
	ExpiresAt        time.Time `json:"expiresAt"`
	RefreshExpiresAt time.Time `json:"-"`
}

// AuthService defines the authentication service interface
type AuthService interface {
	Login(ctx context.Context, username, password string) (*TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)
	ValidateToken(tokenString string) (*Claims, error)
	ValidateAccessToken(tokenString string) (*Claims, error)
	ValidateRefreshToken(tokenString string) (*Claims, error)
	Logout(ctx context.Context, refreshToken, accessToken string) error
	StartCleanup(ctx context.Context)
	StopCleanup()
}

// authService implements AuthService
type authService struct {
	jwtSecret          []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
	users              map[string]string // username -> bcrypt password hash
	dummyPasswordHash  []byte
	fs                 filesystem.FS
	revocationsPath    string
	revokedRefresh     map[string]time.Time
	revokedAccess      map[string]time.Time
	loginFailures      map[string]loginFailure
	mu                 sync.RWMutex
	stopCh             chan struct{}
	wg                 sync.WaitGroup
}

type loginFailure struct {
	count       int
	lockedUntil time.Time
}

// AuthServiceConfig holds configuration for the auth service.
type AuthServiceConfig struct {
	DataDir            string
	JWTSecret          string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Users              map[string]string // username -> bcrypt password hash
}

// NewAuthService creates a new authentication service and loads its revocations.
func NewAuthService(fsys filesystem.FS, cfg AuthServiceConfig) (AuthService, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = config.DefaultDataDir
	}
	if cfg.AccessTokenExpiry == 0 {
		cfg.AccessTokenExpiry = config.DefaultAccessTokenExpiry
	}
	if cfg.RefreshTokenExpiry == 0 {
		cfg.RefreshTokenExpiry = config.DefaultRefreshTokenExpiry
	}
	if cfg.Users == nil {
		cfg.Users = make(map[string]string)
	}

	var dummyHash []byte
	for _, configuredHash := range cfg.Users {
		dummyHash = []byte(configuredHash)
		break
	}
	if len(dummyHash) == 0 {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("boxbox-invalid-user-password"), bcrypt.DefaultCost)
	}

	svc := &authService{
		jwtSecret:          []byte(cfg.JWTSecret),
		accessTokenExpiry:  cfg.AccessTokenExpiry,
		refreshTokenExpiry: cfg.RefreshTokenExpiry,
		users:              cfg.Users,
		dummyPasswordHash:  dummyHash,
		fs:                 fsys,
		revocationsPath:    filepath.Join(cfg.DataDir, config.AuthRevocationsFileName),
		revokedRefresh:     make(map[string]time.Time),
		revokedAccess:      make(map[string]time.Time),
		loginFailures:      make(map[string]loginFailure),
		stopCh:             make(chan struct{}),
	}
	if err := svc.loadRevocations(); err != nil {
		return nil, err
	}
	return svc, nil
}

// Login authenticates a user and returns a token pair
func (s *authService) Login(ctx context.Context, username, password string) (*TokenPair, error) {
	storedHash, exists := s.users[username]
	hash := []byte(storedHash)
	if !exists {
		hash = s.dummyPasswordHash
	}

	// Always execute the same expensive comparison, including for unknown and
	// temporarily locked accounts, to avoid username-enumeration timing leaks.
	passwordMatches := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	if !exists {
		return nil, ErrInvalidCredentials
	}

	s.mu.Lock()
	failure := s.loginFailures[username]
	if time.Now().Before(failure.lockedUntil) {
		s.mu.Unlock()
		return nil, ErrInvalidCredentials
	}
	if !passwordMatches {
		failure.count++
		if failure.count >= config.LoginLockoutThreshold {
			exponent := min(failure.count-config.LoginLockoutThreshold, 9)
			delay := config.LoginLockoutBaseDelay * time.Duration(1<<exponent)
			if delay > config.LoginLockoutMaxDelay {
				delay = config.LoginLockoutMaxDelay
			}
			failure.lockedUntil = time.Now().Add(delay)
		}
		s.loginFailures[username] = failure
		s.mu.Unlock()
		return nil, ErrInvalidCredentials
	}
	delete(s.loginFailures, username)
	s.mu.Unlock()

	return s.generateTokenPair(username)
}

// Refresh generates a new token pair from a valid refresh token
func (s *authService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Parse and validate the refresh token
	claims, err := s.validateToken(refreshToken, TokenTypeRefresh)
	if err != nil {
		return nil, err
	}

	// Rotate once. The check-and-revoke is atomic so concurrent replays cannot
	// both mint a new token pair.
	tokenHash := refreshTokenHash(refreshToken)
	s.mu.Lock()
	if _, revoked := s.revokedRefresh[tokenHash]; revoked {
		s.mu.Unlock()
		return nil, ErrTokenRevoked
	}

	pair, err := s.generateTokenPair(claims.Username)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.revokedRefresh[tokenHash] = claims.ExpiresAt.Time
	err = s.persistRevocationsLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return pair, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *authService) ValidateToken(tokenString string) (*Claims, error) {
	return s.validateToken(tokenString, "")
}

func (s *authService) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := s.validateToken(tokenString, TokenTypeAccess)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	_, revoked := s.revokedAccess[claims.ID]
	s.mu.RUnlock()
	if revoked {
		return nil, ErrTokenRevoked
	}
	return claims, nil
}

func (s *authService) ValidateRefreshToken(tokenString string) (*Claims, error) {
	tokenHash := refreshTokenHash(tokenString)
	s.mu.RLock()
	_, revoked := s.revokedRefresh[tokenHash]
	s.mu.RUnlock()
	if revoked {
		return nil, ErrTokenRevoked
	}

	return s.validateToken(tokenString, TokenTypeRefresh)
}

func (s *authService) validateToken(tokenString string, expectedType TokenType) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer("boxbox"))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid || claims.ExpiresAt == nil || claims.ExpiresAt.Time.IsZero() {
		return nil, ErrInvalidToken
	}
	if expectedType != "" && claims.TokenType != expectedType {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// Logout revokes a refresh token and, when supplied, the current access token.
func (s *authService) Logout(ctx context.Context, refreshToken, accessToken string) error {
	refreshClaims, err := s.validateToken(refreshToken, TokenTypeRefresh)
	if err != nil {
		return err
	}

	refreshHash := refreshTokenHash(refreshToken)
	var accessClaims *Claims
	if accessToken != "" {
		claims, err := s.validateToken(accessToken, TokenTypeAccess)
		if err == nil && claims.Username == refreshClaims.Username && claims.ID != "" {
			accessClaims = claims
		}
	}

	s.mu.Lock()
	if _, revoked := s.revokedRefresh[refreshHash]; revoked {
		s.mu.Unlock()
		return ErrTokenRevoked
	}
	s.revokedRefresh[refreshHash] = refreshClaims.ExpiresAt.Time
	if accessClaims != nil {
		s.revokedAccess[accessClaims.ID] = accessClaims.ExpiresAt.Time
	}
	err = s.persistRevocationsLocked()
	s.mu.Unlock()
	return err
}

// generateTokenPair creates a new access and refresh token pair
func (s *authService) generateTokenPair(username string) (*TokenPair, error) {
	now := time.Now()
	userID := generateUserID(username)

	// Create access token
	accessExpiry := now.Add(s.accessTokenExpiry)
	accessClaims := &Claims{
		UserID:    userID,
		Username:  username,
		TokenType: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        generateTokenID(),
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "boxbox",
			Subject:   username,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(s.jwtSecret)
	if err != nil {
		return nil, err
	}

	// Create refresh token
	refreshExpiry := now.Add(s.refreshTokenExpiry)
	refreshClaims := &Claims{
		UserID:    userID,
		Username:  username,
		TokenType: TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        generateTokenID(),
			ExpiresAt: jwt.NewNumericDate(refreshExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "boxbox",
			Subject:   username,
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(s.jwtSecret)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:      accessTokenString,
		RefreshToken:     refreshTokenString,
		ExpiresAt:        accessExpiry,
		RefreshExpiresAt: refreshExpiry,
	}, nil
}

// generateUserID creates a stable, non-plaintext user ID for token claims.
func generateUserID(username string) string {
	sum := sha256.Sum256([]byte(username))
	return hex.EncodeToString(sum[:8])
}

func generateTokenID() string {
	return uuid.New().String()
}

// CleanupExpiredTokens removes expired tokens from the revoked list
// Should be called periodically to prevent memory growth
func (s *authService) CleanupExpiredTokens() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	refreshCount := len(s.revokedRefresh)
	accessCount := len(s.revokedAccess)
	maps.DeleteFunc(s.revokedRefresh, func(_ string, expiresAt time.Time) bool {
		return !expiresAt.After(now)
	})
	maps.DeleteFunc(s.revokedAccess, func(_ string, expiresAt time.Time) bool {
		return !expiresAt.After(now)
	})
	maps.DeleteFunc(s.loginFailures, func(_ string, failure loginFailure) bool {
		return failure.count == 0 || now.Sub(failure.lockedUntil) > config.LoginLockoutMaxDelay
	})
	if refreshCount != len(s.revokedRefresh) || accessCount != len(s.revokedAccess) {
		return s.persistRevocationsLocked()
	}
	return nil
}

// StartCleanup starts the periodic cleanup of expired tokens
func (s *authService) StartCleanup(ctx context.Context) {
	s.wg.Go(func() {
		ticker := time.NewTicker(config.TokenCleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-ticker.C:
				if err := s.CleanupExpiredTokens(); err != nil {
					log.Warn().Err(err).Msg("Could not persist auth token cleanup")
				}
			}
		}
	})
}

// StopCleanup stops the cleanup goroutine
func (s *authService) StopCleanup() {
	close(s.stopCh)
	s.wg.Wait()
}
