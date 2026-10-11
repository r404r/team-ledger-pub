package configfile

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// Read checks and reads the same descriptor. Linux secrets must be service-owned
// 0400/0600 regular files; public trust anchors may be root/service-owned but
// must not be writable by group or other users.
func Read(path string, limit int, confidential bool) ([]byte, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, errors.New("invalid protected file")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid protected file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode().Perm()
	if !ok {
		return nil, errors.New("invalid protected file")
	}
	if confidential {
		if stat.Uid != uint32(os.Geteuid()) || (mode != 0400 && mode != 0600) {
			return nil, errors.New("invalid protected file")
		}
	} else if (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) || mode&0022 != 0 {
		return nil, errors.New("invalid trust file")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if e != nil || len(b) == 0 || len(b) > limit {
		clear(b)
		return nil, errors.New("invalid protected file size")
	}
	return b, nil
}
