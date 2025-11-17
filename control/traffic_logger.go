package control

import (
	"encoding/csv"
	"os"
	"strconv"
	"sync"
	"time"
)

type TrafficKey struct {
	Src string
	Dst string
	Dir string // "up" or "down"
}

type TrafficLogger struct {
	mu       sync.Mutex
	file     *os.File
	writer   *csv.Writer
	interval time.Duration
	records  map[TrafficKey]int64
	ticker   *time.Ticker
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

func NewTrafficLogger(path string, interval time.Duration) (*TrafficLogger, error) {
	newFile := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		newFile = true
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	writer := csv.NewWriter(f)
	if newFile {
		writer.Write([]string{"timestamp", "src", "dst", "dir", "bytes"})
		writer.Flush()
	}

	tl := &TrafficLogger{
		file:     f,
		writer:   writer,
		interval: interval,
		records:  make(map[TrafficKey]int64),
		ticker:   time.NewTicker(interval),
		stopCh:   make(chan struct{}),
	}

	tl.wg.Add(1)
	go tl.run()
	return tl, nil
}

func (t *TrafficLogger) Log(src, dst, dir string, bytes int64) {
	if bytes > 0 {
		t.mu.Lock()
		defer t.mu.Unlock()
		key := TrafficKey{Src: src, Dst: dst, Dir: dir}
		t.records[key] += bytes
	}
}

func (t *TrafficLogger) run() {
	defer t.wg.Done()
	for {
		select {
		case <-t.ticker.C:
			t.flush()
		case <-t.stopCh:
			t.flush()
			return
		}
	}
}

func (t *TrafficLogger) flush() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.records) == 0 {
		return
	}

	for key, bytes := range t.records {
		t.writer.Write([]string{
			time.Now().Format("2006-01-02 15:04:05"),
			key.Src,
			key.Dst,
			key.Dir,
			strconv.FormatInt(bytes, 10),
		})
	}
	t.writer.Flush()

	t.records = make(map[TrafficKey]int64) // reset
}

func (t *TrafficLogger) Close() {
	close(t.stopCh)
	t.ticker.Stop()
	t.wg.Wait()
	t.file.Close()
}
