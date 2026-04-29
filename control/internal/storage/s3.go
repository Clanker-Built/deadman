// Package storage is the object-storage abstraction layer.
//
// Current M2 scope: S3-compatible backend (MinIO in dev, R2/B2/S3 in prod).
// DualWriter writes the same payload to primary + backup concurrently; if
// backup fails the call still returns success with a warning so user uploads
// aren't blocked by a single-provider outage. A nightly verifier (M4) will
// reconcile.
package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func newSHA256() hash.Hash { return sha256.New() }

// Config describes one S3-compatible backend.
type Config struct {
	Endpoint        string // empty for AWS S3
	Region          string // "auto" for R2, "us-east-1" dev default
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	// PathStyle: true for MinIO, Cloudflare R2, and most S3-compat servers.
	PathStyle bool
}

// Client wraps an S3 client plus its bucket.
type Client struct {
	c      *s3.Client
	bucket string
}

// New constructs a client for the given backend.
func New(ctx context.Context, cfg Config) (*Client, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	s3c := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.PathStyle
	})
	return &Client{c: s3c, bucket: cfg.Bucket}, nil
}

// EnsureBucket creates the bucket if it doesn't exist.
func (c *Client) EnsureBucket(ctx context.Context) error {
	_, err := c.c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(c.bucket)})
	if err == nil {
		return nil
	}
	_, err = c.c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(c.bucket)})
	return err
}

// Put uploads bytes at key. Returns the computed ETag.
func (c *Client) Put(ctx context.Context, key string, body io.ReadSeeker, contentType string) (string, error) {
	out, err := c.c.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return "", err
	}
	if out.ETag == nil {
		return "", nil
	}
	return *out.ETag, nil
}

// Get streams an object.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := c.c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

// URI returns an s3://bucket/key pointer for DB storage.
func (c *Client) URI(key string) string {
	return "s3://" + c.bucket + "/" + key
}

// RawS3 exposes the underlying S3 client for operations (Delete, List, etc.)
// that aren't wrapped by this package. Intended for admin jobs and tests.
func (c *Client) RawS3() *s3.Client { return c.c }

// Bucket returns the bucket name.
func (c *Client) Bucket() string { return c.bucket }

// DualWriter writes to a primary + optional backup. Errors on primary are
// fatal; errors on backup are surfaced as BackupErr but don't fail the call.
//
// Also serves as a DualReader: Get tries primary first then falls back to
// backup. Used by the release worker so a primary-storage outage doesn't
// block release (§29.3).
type DualWriter struct {
	Primary *Client
	Backup  *Client
	Logger  *slog.Logger
}

// Get returns a stream for key, trying Primary first and Backup on error.
// The returned source is "primary" or "backup" so callers can audit which
// side served the read.
func (d *DualWriter) Get(ctx context.Context, key string) (io.ReadCloser, string, error) {
	if d.Primary != nil {
		r, err := d.Primary.Get(ctx, key)
		if err == nil {
			return r, "primary", nil
		}
		if d.Logger != nil {
			d.Logger.Warn("primary read failed; trying backup", "key", key, "err", err)
		}
	}
	if d.Backup != nil {
		r, err := d.Backup.Get(ctx, key)
		if err == nil {
			return r, "backup", nil
		}
		return nil, "", fmt.Errorf("both primary and backup failed: %w", err)
	}
	return nil, "", errors.New("storage: no readable backend")
}

// HeadSHA256 returns the SHA-256 of the object at key on this specific
// client. Streams the body; does not buffer. Used by the consistency
// verifier to compare primary vs backup without trusting either ETag.
func (c *Client) HeadSHA256(ctx context.Context, key string) ([32]byte, int64, error) {
	var h [32]byte
	body, err := c.Get(ctx, key)
	if err != nil {
		return h, 0, err
	}
	defer body.Close()
	hasher := newSHA256()
	n, err := io.Copy(hasher, body)
	if err != nil {
		return h, 0, err
	}
	copy(h[:], hasher.Sum(nil))
	return h, n, nil
}

// WriteResult is returned by DualWriter.Put.
type WriteResult struct {
	PrimaryURI string
	BackupURI  string
	PrimaryETag string
	BackupETag  string
	BackupErr   error
}

// Put writes body to both backends concurrently with the same key.
func (d *DualWriter) Put(ctx context.Context, key string, body []byte, contentType string) (*WriteResult, error) {
	if d.Primary == nil {
		return nil, errors.New("storage: primary not configured")
	}
	out := &WriteResult{}
	var backupErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		etag, err := d.Primary.Put(ctx, key, newSeeker(body), contentType)
		if err != nil {
			backupErr = err // signal via a local; primary err is fatal though
			return
		}
		out.PrimaryURI = d.Primary.URI(key)
		out.PrimaryETag = etag
	}()

	if d.Backup != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			etag, err := d.Backup.Put(ctx, key, newSeeker(body), contentType)
			if err != nil {
				out.BackupErr = err
				if d.Logger != nil {
					d.Logger.Warn("backup write failed", "key", key, "err", err)
				}
				return
			}
			out.BackupURI = d.Backup.URI(key)
			out.BackupETag = etag
		}()
	}
	wg.Wait()

	if out.PrimaryURI == "" {
		return nil, fmt.Errorf("primary write failed: %w", backupErr)
	}
	return out, nil
}

// newSeeker wraps a byte slice as an io.ReadSeeker so both goroutines can
// independently rewind.
func newSeeker(b []byte) io.ReadSeeker { return &seeker{b: b} }

type seeker struct {
	b   []byte
	pos int64
}

func (s *seeker) Read(p []byte) (int, error) {
	if s.pos >= int64(len(s.b)) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.pos:])
	s.pos += int64(n)
	return n, nil
}
func (s *seeker) Seek(off int64, whence int) (int64, error) {
	var n int64
	switch whence {
	case io.SeekStart:
		n = off
	case io.SeekCurrent:
		n = s.pos + off
	case io.SeekEnd:
		n = int64(len(s.b)) + off
	}
	if n < 0 || n > int64(len(s.b)) {
		return 0, errors.New("seek out of range")
	}
	s.pos = n
	return n, nil
}
