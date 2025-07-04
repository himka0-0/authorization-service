package util

import "time"

func AbsDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
