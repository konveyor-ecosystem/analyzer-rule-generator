# Go io/ioutil Package Deprecation Guide

**Migration from io/ioutil to io and os packages**

As of Go 1.16, the `io/ioutil` package has been deprecated. The functionality has been moved to the `io` and `os` packages for better organization.

## Package Import Changes

### Remove io/ioutil import

The `io/ioutil` package should no longer be imported. Replace it with `io` and/or `os` imports.

**Before:**
```go
import "io/ioutil"
```

**After:**
```go
import (
    "io"
    "os"
)
```

## Function Replacements

### ioutil.ReadFile → os.ReadFile

Replace `ioutil.ReadFile()` with `os.ReadFile()`.

**Before:**
```go
data, err := ioutil.ReadFile("file.txt")
```

**After:**
```go
data, err := os.ReadFile("file.txt")
```

### ioutil.WriteFile → os.WriteFile

Replace `ioutil.WriteFile()` with `os.WriteFile()`.

**Before:**
```go
err := ioutil.WriteFile("file.txt", data, 0644)
```

**After:**
```go
err := os.WriteFile("file.txt", data, 0644)
```

### ioutil.ReadAll → io.ReadAll

Replace `ioutil.ReadAll()` with `io.ReadAll()`.

**Before:**
```go
data, err := ioutil.ReadAll(reader)
```

**After:**
```go
data, err := io.ReadAll(reader)
```

### ioutil.ReadDir → os.ReadDir

Replace `ioutil.ReadDir()` with `os.ReadDir()`.

**Before:**
```go
files, err := ioutil.ReadDir(".")
```

**After:**
```go
files, err := os.ReadDir(".")
```

### ioutil.TempFile → os.CreateTemp

Replace `ioutil.TempFile()` with `os.CreateTemp()`.

**Before:**
```go
tmpfile, err := ioutil.TempFile("", "example")
```

**After:**
```go
tmpfile, err := os.CreateTemp("", "example")
```

### ioutil.TempDir → os.MkdirTemp

Replace `ioutil.TempDir()` with `os.MkdirTemp()`.

**Before:**
```go
dir, err := ioutil.TempDir("", "example")
```

**After:**
```go
dir, err := os.MkdirTemp("", "example")
```

### ioutil.NopCloser → io.NopCloser

Replace `ioutil.NopCloser()` with `io.NopCloser()`.

**Before:**
```go
rc := ioutil.NopCloser(bytes.NewReader(data))
```

**After:**
```go
rc := io.NopCloser(bytes.NewReader(data))
```

### ioutil.Discard → io.Discard

Replace `ioutil.Discard` with `io.Discard`.

**Before:**
```go
io.Copy(ioutil.Discard, reader)
```

**After:**
```go
io.Copy(io.Discard, reader)
```

## References

- [io/ioutil package documentation](https://pkg.go.dev/io/ioutil)
- [Go 1.16 Release Notes](https://go.dev/doc/go1.16)
