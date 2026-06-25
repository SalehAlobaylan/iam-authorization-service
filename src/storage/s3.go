// Package storage provides a thin S3-compatible writer for user avatars.
//
// It reuses the platform's STORAGE_* contract (MinIO locally, S3/Supabase in
// prod) and only does what IAM needs: write a small image and hand back its
// public URL. When no endpoint is configured the store is disabled and callers
// treat avatar upload as unavailable rather than failing to boot.
package storage

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Settings carries the resolved STORAGE_* values.
type Settings struct {
	Endpoint  string
	Region    string
	AccessKey string
	SecretKey string
	Bucket    string
	PublicURL string
}

// AvatarStore writes avatar images to an S3-compatible bucket and returns their
// public URL.
type AvatarStore struct {
	client    *s3.Client
	bucket    string
	publicURL string
}

// NewAvatarStore builds an S3 client for the given settings. It returns
// (nil, nil) when no endpoint is configured so the service can boot without
// object storage and report avatar upload as disabled.
func NewAvatarStore(s Settings) (*AvatarStore, error) {
	if strings.TrimSpace(s.Endpoint) == "" {
		return nil, nil
	}

	region := strings.TrimSpace(s.Region)
	if region == "" {
		region = "us-east-1"
	}
	bucket := strings.TrimSpace(s.Bucket)
	if bucket == "" {
		bucket = "wahb-media"
	}
	endpoint := strings.TrimRight(strings.TrimSpace(s.Endpoint), "/")
	publicURL := strings.TrimRight(strings.TrimSpace(s.PublicURL), "/")
	if publicURL == "" {
		publicURL = endpoint
	}

	// Path-style addressing is required for MinIO and keeps URLs predictable
	// across S3-compatible backends.
	client := s3.New(s3.Options{
		Region:       region,
		Credentials:  credentials.NewStaticCredentialsProvider(s.AccessKey, s.SecretKey, ""),
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
	})

	return &AvatarStore{client: client, bucket: bucket, publicURL: publicURL}, nil
}

// Enabled reports whether avatar storage is configured.
func (a *AvatarStore) Enabled() bool { return a != nil && a.client != nil }

// Put uploads data under key and returns the object's public URL. Objects are
// written public-read so the avatar can be fetched directly by an <img> tag.
func (a *AvatarStore) Put(ctx context.Context, key, contentType string, data []byte) (string, error) {
	if !a.Enabled() {
		return "", fmt.Errorf("avatar storage is not configured")
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err := a.client.PutObject(cctx, &s3.PutObjectInput{
		Bucket:      aws.String(a.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
		ACL:         types.ObjectCannedACLPublicRead,
	})
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s/%s", a.publicURL, a.bucket, key), nil
}
