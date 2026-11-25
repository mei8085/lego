package wait

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/go-acme/lego/v5/log"
)

// For polls the given function 'f', once every 'interval', up to 'timeout'.
func For(timeout, interval time.Duration, f func() (bool, error)) error {
	var lastErr error

	timeUp := time.After(timeout)

	for {
		select {
		case <-timeUp:
			if lastErr == nil {
				return errors.New("time limit exceeded")
			}

			return fmt.Errorf("time limit exceeded: last error: %w", lastErr)
		default:
		}

		stop, err := f()
		if stop {
			return err
		}

		if err != nil {
			log.Debug("Waiting for condition failed.", log.ErrorAttr(err))

			lastErr = err
		}

		time.Sleep(interval)
	}
}

// ForNext polls the given function 'f', once every 'interval', up to 'timeout'.
// The internal is modified with the duration returned by 'f'.
func ForNext(timeout, interval time.Duration, f func() (bool, time.Duration, error)) error {
	var lastErr error

	timeUp := time.After(timeout)

	for {
		select {
		case <-timeUp:
			if lastErr == nil {
				return errors.New("time limit exceeded")
			}

			return fmt.Errorf("time limit exceeded: last error: %w", lastErr)
		default:
		}

		stop, next, err := f()
		if stop {
			return err
		}

		if err != nil {
			log.Debug("Waiting for condition failed.", log.ErrorAttr(err))

			lastErr = err
		}

		time.Sleep(cmp.Or(next, interval))
	}
}

// ForNextContext polls the given function 'f', once every 'interval', up to 'timeout'.
// The interval is modified with the duration returned by 'f'
// (typically the server-suggested Retry-After), but it can never exceed
// the remaining time budget, so a server recommendation cannot extend
// the caller-supplied timeout.
//
// Unlike [ForNext], the polling stops as soon as the context is canceled
// (or reaches its deadline), and every wait is interruptible by the context.
func ForNextContext(ctx context.Context, timeout, interval time.Duration, f func() (bool, time.Duration, error)) error {
	var lastErr error

	deadline := time.Now().Add(timeout)

	ctxDeadline, hasContextDeadline := ctx.Deadline()
	if hasContextDeadline && ctxDeadline.Before(deadline) {
		// The caller's context deadline always takes precedence over the timeout.
		deadline = ctxDeadline
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		now := time.Now()
		if !now.Before(deadline) {
			if hasContextDeadline {
				// The effective deadline came from the context.
				// Report the context error when available, otherwise
				// fall back to the generic time limit error.
				if err := ctx.Err(); err != nil {
					return err
				}

				return context.DeadlineExceeded
			}

			if lastErr == nil {
				return errors.New("time limit exceeded")
			}

			return fmt.Errorf("time limit exceeded: last error: %w", lastErr)
		}

		stop, next, err := f()
		if stop {
			return err
		}

		if err != nil {
			log.Debug("Waiting for condition failed.", log.ErrorAttr(err))

			lastErr = err
		}

		// Clamp the suggested delay to the remaining budget so that a
		// server-suggested Retry-After cannot extend the caller's time limit.
		waitDuration := cmp.Or(next, interval)
		if remaining := deadline.Sub(time.Now()); waitDuration > remaining {
			waitDuration = remaining
		}

		if waitDuration > 0 {
			timer := time.NewTimer(waitDuration)

			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
				// Loop back: the context and the deadline are re-checked
				// at the top of the next iteration.
			}
		}
	}
}

// SleepContext waits for the given duration, but returns early when the
// context is canceled or its deadline is reached.
// The duration is clamped to the remaining time of the context deadline,
// so the wait can never exceed the caller's time limit.
//
// When the wait is bounded by a reached context deadline,
// [context.DeadlineExceeded] is always returned, independently of the
// internal scheduling of the deadline and the wait timer.
func SleepContext(ctx context.Context, duration time.Duration) error {
	clamped := false

	if deadline, ok := ctx.Deadline(); ok {
		waitEnd := time.Now().Add(duration)
		if !deadline.After(waitEnd) {
			// The requested wait would reach (or pass) the context deadline:
			// clamp it, and report the reached deadline afterwards.
			duration = deadline.Sub(time.Now())
			clamped = true
		}
	}

	if duration <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		if clamped {
			// The wait was bounded by the context deadline.
			return context.DeadlineExceeded
		}

		return nil
	}
}

// Retry retries the given operation until it succeeds or the context is canceled.
// Similar to [backoff.Retry] but with a different signature.
func Retry(ctx context.Context, operation func() error, opts ...backoff.RetryOption) error {
	_, err := backoff.Retry(ctx, func() (any, error) {
		return nil, operation()
	}, opts...)

	return err
}

func SimpleNotify(message string) backoff.Notify {
	return func(err error, duration time.Duration) {
		log.Debug(message, log.ErrorAttr(err), log.DurationAttr("duration", duration))
	}
}
