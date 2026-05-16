package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Env      string         `yaml:"env"`
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	JWT      JWTConfig      `yaml:"jwt"`
	Tenancy  TenancyConfig  `yaml:"tenancy"`
	Email    EmailConfig    `yaml:"email"`
}

type EmailConfig struct {
	SMTPHost             string `yaml:"smtp_host"`
	SMTPPort             string `yaml:"smtp_port"`
	SMTPPassword         string `yaml:"smtp_password"`
	FromAddress          string `yaml:"from_address"`
	VerificationBaseURL  string `yaml:"verification_base_url"`
	ResetBaseURL         string `yaml:"reset_base_url"`
	RequireVerification  bool   `yaml:"require_verification"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Host string `yaml:"host"`
}

type DatabaseConfig struct {
	URL                  string `yaml:"url"`
	Host                 string `yaml:"host"`
	Port                 string `yaml:"port"`
	User                 string `yaml:"user"`
	Password             string `yaml:"password"`
	DBName               string `yaml:"dbname"`
	SSLMode              string `yaml:"sslmode"`
	PreferSimpleProtocol bool   `yaml:"prefer_simple_protocol"`
}

type JWTConfig struct {
	Secret          string `yaml:"secret"`
	AccessTokenTTL  int    `yaml:"access_token_ttl"`  // in seconds
	RefreshTokenTTL int    `yaml:"refresh_token_ttl"` // in seconds
	Issuer          string `yaml:"issuer"`
	Audience        string `yaml:"audience"`
}

type TenancyConfig struct {
	DefaultTenantID string `yaml:"default_tenant_id"`
}

/*
* Load aggregates application configuration into a single Config struct.
* It reads base values from a YAML file on disk using CONFIG_PATH when set,
* falling back to the default path config/config.yaml when CONFIG_PATH is empty.
* After parsing the YAML into cfg, it selectively overrides fields with values
* from environment variables (for example PORT, DB_HOST, DB_USER, DB_PASSWORD,
* DB_NAME, DB_SSLMODE, JWT_SECRET, ENV) when they are present.
* This pattern allows you to keep sensible local defaults in config.yaml while
* still customizing behavior per environment (Docker, staging, production)
* without modifying the file itself.
* On success it returns a pointer to the populated Config; on failure it
* returns a wrapped error that describes whether reading or parsing failed.
 */
func Load() (*Config, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "src/config/config.yaml"
	}

	var cfg Config
	file, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(file, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
	}

	// Override with environment variables
	if port := os.Getenv("PORT"); port != "" {
		cfg.Server.Port = port
	}
	if host := os.Getenv("HOST"); host != "" {
		cfg.Server.Host = host
	}
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		cfg.Database.URL = dbURL
	}
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		cfg.Database.Host = dbHost
	}
	if dbPort := os.Getenv("DB_PORT"); dbPort != "" {
		cfg.Database.Port = dbPort
	}
	if dbUser := os.Getenv("DB_USER"); dbUser != "" {
		cfg.Database.User = dbUser
	}
	if dbPass := os.Getenv("DB_PASSWORD"); dbPass != "" {
		cfg.Database.Password = dbPass
	}
	if dbName := os.Getenv("DB_NAME"); dbName != "" {
		cfg.Database.DBName = dbName
	}
	if dbSSL := os.Getenv("DB_SSLMODE"); dbSSL != "" {
		cfg.Database.SSLMode = dbSSL
	}
	if simpleProtocol := os.Getenv("DB_PREFER_SIMPLE_PROTOCOL"); simpleProtocol != "" {
		if value, parseErr := strconv.ParseBool(strings.TrimSpace(simpleProtocol)); parseErr == nil {
			cfg.Database.PreferSimpleProtocol = value
		}
	}
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.JWT.Secret = jwtSecret
	}
	if jwtIssuer := os.Getenv("JWT_ISSUER"); jwtIssuer != "" {
		cfg.JWT.Issuer = jwtIssuer
	}
	if jwtAudience := os.Getenv("JWT_AUDIENCE"); jwtAudience != "" {
		cfg.JWT.Audience = jwtAudience
	}
	if defaultTenantID := os.Getenv("DEFAULT_TENANT_ID"); defaultTenantID != "" {
		cfg.Tenancy.DefaultTenantID = defaultTenantID
	}
	if env := os.Getenv("ENV"); env != "" {
		cfg.Env = env
	}

	// Email config overrides
	if smtpHost := os.Getenv("SMTP_HOST"); smtpHost != "" {
		cfg.Email.SMTPHost = smtpHost
	}
	if smtpPort := os.Getenv("SMTP_PORT"); smtpPort != "" {
		cfg.Email.SMTPPort = smtpPort
	}
	if smtpPass := os.Getenv("SMTP_PASSWORD"); smtpPass != "" {
		cfg.Email.SMTPPassword = smtpPass
	}
	if fromAddr := os.Getenv("EMAIL_FROM"); fromAddr != "" {
		cfg.Email.FromAddress = fromAddr
	}
	if verifyURL := os.Getenv("EMAIL_VERIFICATION_BASE_URL"); verifyURL != "" {
		cfg.Email.VerificationBaseURL = verifyURL
	}
	if resetURL := os.Getenv("EMAIL_RESET_BASE_URL"); resetURL != "" {
		cfg.Email.ResetBaseURL = resetURL
	}
	if requireVerify := os.Getenv("REQUIRE_EMAIL_VERIFICATION"); requireVerify != "" {
		if value, parseErr := strconv.ParseBool(strings.TrimSpace(requireVerify)); parseErr == nil {
			cfg.Email.RequireVerification = value
		}
	}

	if cfg.JWT.Issuer == "" {
		cfg.JWT.Issuer = "iam-authorization-service"
	}
	if cfg.Tenancy.DefaultTenantID == "" {
		cfg.Tenancy.DefaultTenantID = "default"
	}
	if strings.Contains(cfg.Database.URL, "pooler.supabase.com:6543") {
		cfg.Database.PreferSimpleProtocol = true
	}

	if err := validateJWTSecret(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validateJWTSecret refuses to start with an empty or well-known placeholder
// JWT secret outside of development/test environments. CMS verifies tokens
// using the same secret, so a mismatch or default value allows token forgery.
func validateJWTSecret(cfg *Config) error {
	secret := strings.TrimSpace(cfg.JWT.Secret)
	env := strings.ToLower(strings.TrimSpace(cfg.Env))
	isDev := env == "development" || env == "dev" || env == "test"

	if secret == "" {
		return fmt.Errorf("JWT secret is required: set JWT_SECRET env or jwt.secret in config.yaml")
	}

	knownPlaceholders := []string{
		"your-secret-key-change-in-production",
		"your-secret-key-change-this",
		"change-me",
		"changeme",
		"dev_jwt_secret_change_me",
	}
	for _, placeholder := range knownPlaceholders {
		if strings.EqualFold(secret, placeholder) {
			if isDev {
				fmt.Printf("[IAM] WARNING: using placeholder JWT secret %q — only acceptable in development\n", placeholder)
				return nil
			}
			return fmt.Errorf("refusing to start: JWT secret is a well-known placeholder %q; set a strong JWT_SECRET", placeholder)
		}
	}

	if !isDev && len(secret) < 32 {
		return fmt.Errorf("refusing to start: JWT_SECRET must be at least 32 characters in %q environment (got %d)", cfg.Env, len(secret))
	}

	return nil
}
