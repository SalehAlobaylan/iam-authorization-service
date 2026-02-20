package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Env      string         `yaml:"env"`
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	JWT      JWTConfig      `yaml:"jwt"`
	Tenancy  TenancyConfig  `yaml:"tenancy"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Host string `yaml:"host"`
}

type DatabaseConfig struct {
	URL      string `yaml:"url"`
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"sslmode"`
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

	file, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(file, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
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

	if cfg.JWT.Issuer == "" {
		cfg.JWT.Issuer = "iam-authorization-service"
	}
	if cfg.Tenancy.DefaultTenantID == "" {
		cfg.Tenancy.DefaultTenantID = "default"
	}

	return &cfg, nil
}
