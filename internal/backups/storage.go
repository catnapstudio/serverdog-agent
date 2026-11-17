package backups

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type bucket struct {
	client *minio.Client
	s      Storage
}

func open(s Storage) (*bucket, error) {
	host, secure, err := endpoint(s.Endpoint)
	if err != nil {
		return nil, err
	}

	client, err := minio.New(host, &minio.Options{Creds: credentials.NewStaticV4(s.AccessKey, s.SecretKey, ""), Secure: secure, Region: s.Region})
	if err != nil {
		return nil, fmt.Errorf("Couldn't reach the storage: %w", err)
	}

	return &bucket{client: client, s: s}, nil
}

// key is an object's name: the plan's folder in the bucket's prefix, then the run's folder.
func (b *bucket) key(parts ...string) string {
	return path.Join(append([]string{b.s.Prefix}, parts...)...)
}

func (b *bucket) upload(ctx context.Context, key, file string) error {
	if _, err := b.client.FPutObject(ctx, b.s.Bucket, key, file, minio.PutObjectOptions{ContentType: "application/gzip"}); err != nil {
		return fmt.Errorf("Couldn't upload %s: %w", path.Base(key), err)
	}

	return nil
}

// Test writes and deletes a small object, which is what a backup needs the keys to allow.
func Test(ctx context.Context, s Storage) error {
	if err := validateStorage(s); err != nil {
		return err
	}

	b, err := open(s)
	if err != nil {
		return err
	}

	key := b.key(".serverdog-test")
	if _, err := b.client.PutObject(ctx, s.Bucket, key, bytes.NewReader([]byte("ok")), 2, minio.PutObjectOptions{}); err != nil {
		return fmt.Errorf("The storage refused a test upload: %w", err)
	}
	if err := b.client.RemoveObject(ctx, s.Bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("The storage took a test upload but refused to delete it: %w", err)
	}

	return nil
}

// prune deletes the plan's oldest run folders beyond keep. Folder names are UTC timestamps, so they sort by age.
func (b *bucket) prune(ctx context.Context, planID string, keep int) error {
	base := b.key(planID) + "/"
	objects := map[string][]string{}

	for object := range b.client.ListObjects(ctx, b.s.Bucket, minio.ListObjectsOptions{Prefix: base, Recursive: true}) {
		if object.Err != nil {
			return fmt.Errorf("Couldn't list the old backups: %w", object.Err)
		}
		folder, _, _ := strings.Cut(strings.TrimPrefix(object.Key, base), "/")
		objects[folder] = append(objects[folder], object.Key)
	}

	folders := make([]string, 0, len(objects))
	for folder := range objects {
		folders = append(folders, folder)
	}
	slices.Sort(folders)
	slices.Reverse(folders)

	for _, folder := range folders[min(keep, len(folders)):] {
		for _, key := range objects[folder] {
			if err := b.client.RemoveObject(ctx, b.s.Bucket, key, minio.RemoveObjectOptions{}); err != nil {
				return fmt.Errorf("Couldn't delete the old backup %s: %w", folder, err)
			}
		}
	}

	return nil
}
