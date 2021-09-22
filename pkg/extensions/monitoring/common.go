package monitoring

import (
	"math"
	"os"
	"path/filepath"
)

func GetDefaultBuckets() []float64 {
	return []float64{.05, .5, 1, 5, 30, 60, 600, math.MaxFloat64}
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})

	return size, err
}
