package wait

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFor_timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		var io atomic.Int64

		err := For(3*time.Second, 1*time.Second, func() (bool, error) {
			io.Add(1)

			return false, nil
		})

		assert.Equal(t, 3*time.Second, time.Since(now))
		require.EqualValues(t, 3, io.Load())
		require.EqualError(t, err, "time limit exceeded")
	})
}

func TestFor_timeout_with_error(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		var io atomic.Int64

		err := For(3*time.Second, 1*time.Second, func() (bool, error) {
			io.Add(1)

			// This allows be sure that the latest previous error is returned.
			if io.Load() == 1 {
				return false, errors.New("oops")
			}

			return false, nil
		})

		assert.Equal(t, 3*time.Second, time.Since(now))
		require.EqualValues(t, 3, io.Load())
		require.EqualError(t, err, "time limit exceeded: last error: oops")
	})
}

func TestFor_stop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		var io atomic.Int64

		err := For(3*time.Second, 1*time.Second, func() (bool, error) {
			io.Add(1)

			return true, nil
		})

		assert.Equal(t, 0*time.Second, time.Since(now))
		require.NoError(t, err)
		require.EqualValues(t, 1, io.Load())
	})
}

func TestFor_stop_with_error(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		var io atomic.Int64

		err := For(3*time.Second, 1*time.Second, func() (bool, error) {
			io.Add(1)

			return true, errors.New("oops")
		})

		assert.Equal(t, 0*time.Second, time.Since(now))
		require.EqualError(t, err, "oops")
		require.EqualValues(t, 1, io.Load())
	})
}

func TestForNext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		var io atomic.Int64

		err := ForNext(3*time.Second, 1*time.Second, func() (bool, time.Duration, error) {
			io.Add(1)

			return false, 500 * time.Millisecond, nil
		})

		assert.Equal(t, 3*time.Second, time.Since(now))
		require.EqualValues(t, 6, io.Load())
		require.EqualError(t, err, "time limit exceeded")
	})
}

func TestForNextContext_timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		var io atomic.Int64

		err := ForNextContext(context.Background(), 3*time.Second, 1*time.Second, func() (bool, time.Duration, error) {
			io.Add(1)

			return false, 500 * time.Millisecond, nil
		})

		assert.Equal(t, 3*time.Second, time.Since(now))
		require.EqualValues(t, 6, io.Load())
		require.EqualError(t, err, "time limit exceeded")
	})
}

func TestForNextContext_retryAfterClampedToTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		var io atomic.Int64

		// The function suggests waiting far longer than the timeout.
		// The suggested delay must be clamped so the caller's time limit is honored.
		err := ForNextContext(context.Background(), 2*time.Second, 1*time.Second, func() (bool, time.Duration, error) {
			io.Add(1)

			return false, time.Hour, nil
		})

		assert.Equal(t, 2*time.Second, time.Since(now))
		require.EqualValues(t, 1, io.Load())
		require.EqualError(t, err, "time limit exceeded")
	})
}

func TestForNextContext_contextDeadlineClampsTimeout(t *testing.T) {
	// Uses real time: under testing/synctest the context deadline and the
	// clamped poll timer become ready at the same bubble instant, whose
	// scheduling order is randomized. The contract is about real-time behavior:
	// the caller-supplied timeout (1h) must be bounded by the context deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	now := time.Now()

	var io atomic.Int64

	err := ForNextContext(ctx, time.Hour, 50*time.Millisecond, func() (bool, time.Duration, error) {
		io.Add(1)

		return false, 0, nil
	})

	// The 1h timeout never takes effect: polling stops around the context deadline.
	assert.LessOrEqual(t, time.Since(now), time.Second)
	require.GreaterOrEqual(t, io.Load(), int64(1))
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestForNextContext_contextCanceledDuringWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		ctx, cancel := context.WithCancel(context.Background())

		var io atomic.Int64

		done := make(chan error, 1)

		go func() {
			done <- ForNextContext(ctx, time.Hour, time.Hour, func() (bool, time.Duration, error) {
				io.Add(1)

				return false, time.Hour, nil
			})
		}()

		synctest.Wait()

		cancel()

		err := <-done

		assert.Less(t, time.Since(now), time.Hour)
		require.EqualValues(t, 1, io.Load())
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestForNextContext_stop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		var io atomic.Int64

		err := ForNextContext(context.Background(), 3*time.Second, 1*time.Second, func() (bool, time.Duration, error) {
			io.Add(1)

			return true, 0, errors.New("oops")
		})

		assert.Equal(t, 0*time.Second, time.Since(now))
		require.EqualError(t, err, "oops")
		require.EqualValues(t, 1, io.Load())
	})
}

func TestSleepContext_returnsAfterDuration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()

		err := SleepContext(context.Background(), 2*time.Second)

		require.NoError(t, err)
		assert.Equal(t, 2*time.Second, time.Since(now))
	})
}

func TestSleepContext_clampedToDeadline(t *testing.T) {
	// Uses real time on purpose: under testing/synctest the deadline timer
	// and the clamped wait timer become ready at the same bubble instant,
	// whose scheduling order is randomized and cannot be asserted deterministically.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	now := time.Now()

	// The requested wait far exceeds the context deadline:
	// it must be clamped and never overshoot it.
	err := SleepContext(ctx, time.Hour)

	assert.LessOrEqual(t, time.Since(now), 500*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Once the deadline has been reached, a subsequent wait fails
	// immediately, without any further delay.
	start := time.Now()
	err = SleepContext(ctx, time.Hour)
	assert.Less(t, time.Since(start), 50*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestSleepContext_canceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)

		go func() {
			done <- SleepContext(ctx, time.Hour)
		}()

		synctest.Wait()

		cancel()

		require.ErrorIs(t, <-done, context.Canceled)
	})
}
