module github.com/indago/indago

// Go 1.26+ per spec. The toolchain is resolved automatically (GOTOOLCHAIN=auto);
// the pinned driver modernc.org/sqlite requires >= 1.26.0.
go 1.26.0

require (
	github.com/playwright-community/playwright-go v0.5001.0
	golang.org/x/net v0.59.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/deckarep/golang-set/v2 v2.6.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-jose/go-jose/v3 v3.0.3 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.48.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
