package appserver

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestForegroundServiceShutdownWaitsForCleanup(t *testing.T) {
	for _, trigger := range []string{"stop", "cancel", "server failure"} {
		t.Run(trigger, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := make(chan struct{})
			serverErrors := make(chan error, 1)
			started, stopping, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			failure := errors.New("HTTP listener failed")
			go func() {
				done <- runForegroundService(ctx, stop, serverErrors, func(ctx context.Context) error {
					close(started)
					<-ctx.Done()
					close(stopping)
					<-release
					return ctx.Err()
				})
			}()
			<-started
			switch trigger {
			case "stop":
				close(stop)
			case "cancel":
				cancel()
			case "server failure":
				serverErrors <- failure
			}
			select {
			case <-stopping:
			case <-time.After(5 * time.Second):
				t.Fatal("companion was not cancelled")
			}
			select {
			case err := <-done:
				t.Fatalf("returned before service cleanup: %v", err)
			default:
			}
			close(release)
			err := <-done
			if trigger == "server failure" {
				if !errors.Is(err, failure) {
					t.Fatalf("lost server error: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestForegroundServiceFailures(t *testing.T) {
	failure := errors.New("tunnel failed")
	for _, serviceErr := range []error{failure, nil, context.Canceled} {
		err := runForegroundService(context.Background(), nil, nil, func(context.Context) error { return serviceErr })
		if err == nil || (serviceErr != nil && !errors.Is(err, serviceErr)) {
			t.Fatalf("unexpected service return %v was not propagated: %v", serviceErr, err)
		}
	}
}

func TestForegroundServiceCancelledBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runForegroundService(ctx, nil, nil, func(context.Context) error {
		t.Error("cancelled server started its companion")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestForegroundServiceCleanupFailure(t *testing.T) {
	failure := errors.New("tunnel cleanup failed")
	stop := make(chan struct{})
	close(stop)
	err := runForegroundService(context.Background(), stop, nil, func(ctx context.Context) error {
		<-ctx.Done()
		return errors.Join(ctx.Err(), failure)
	})
	if !errors.Is(err, failure) {
		t.Fatalf("lost cleanup failure: %v", err)
	}
}

func TestForegroundServiceHTTPClosedPreservesCleanupFailure(t *testing.T) {
	failure := errors.New("tunnel cleanup failed")
	serverErrors := make(chan error, 1)
	serverErrors <- http.ErrServerClosed
	err := runForegroundService(context.Background(), nil, serverErrors, func(ctx context.Context) error {
		<-ctx.Done()
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("HTTP close hid cleanup failure: %v", err)
	}
}
