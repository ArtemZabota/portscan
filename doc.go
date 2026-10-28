// Package portscan performs bounded, context-aware TCP connect scans.
//
// A Scanner can be reused concurrently. Its concurrency limit is shared by all
// scans on that instance. DNS names are resolved once per scan, and every unique
// address is scanned. Result order is unspecified.
//
// Callers must drain the results channel or cancel the context. On cancellation,
// delivery is best effort: queued work is abandoned and undelivered results may
// be dropped so that an absent consumer cannot prevent shutdown.
package portscan
