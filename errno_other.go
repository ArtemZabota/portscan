//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris && !windows

package portscan

// On other platforms only portable context/net.Error classification is used.
func isRefused(error) bool        { return false }
func isUnreachable(error) bool    { return false }
func isConnectTimeout(error) bool { return false }
