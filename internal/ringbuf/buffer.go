package ringbuf

import (
	"sync"
)

// maxBufferEntries is the capacity of the ring buffer. When full, the oldest
// entry is overwritten.
const maxBufferEntries = 10_000

// Buffer is a thread-safe ring buffer.
type Buffer[T any] struct {
	mtx      sync.Mutex
	buf      []T
	pos      int
	capacity int
}

func NewWithSize[T any](size int) *Buffer[T] {
	if size <= 0 {
		size = maxBufferEntries
	}
	return &Buffer[T]{
		buf:      make([]T, size),
		capacity: size,
	}
}

func New[T any]() *Buffer[T] {
	return NewWithSize[T](maxBufferEntries)
}

// Record appends a record to the ring buffer. If the buffer is full,
// the oldest entry is overwritten and dropped is returned as true.
func (b *Buffer[T]) Record(rec T) bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	dropped := b.pos >= b.capacity

	b.buf[b.pos%b.capacity] = rec
	b.pos++

	return dropped
}

// Drain returns all buffered records in reverse chronological order (newest first)
// and resets the buffer.
func (b *Buffer[T]) Drain() []T {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	n := min(b.pos, b.capacity)
	if n == 0 {
		return nil
	}

	records := make([]T, 0, n)
	for i := range n {
		idx := (b.pos - 1 - i) % b.capacity
		records = append(records, b.buf[idx])
	}

	b.pos = 0

	return records
}
