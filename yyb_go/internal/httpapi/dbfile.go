package httpapi

import (
	"path/filepath"
	"strings"
)

const DefaultDBFilename = "yyb.db"

// prepareDBPath resolves the SQLite database path. A bare filename is placed
// under dbDir (resource/db); an absolute or path-like value is used as-is.
func prepareDBPath(dbDir, filename string) (string, error) {
	if filename == "" {
		filename = DefaultDBFilename
	}
	if filepath.IsAbs(filename) || strings.ContainsAny(filename, "/\\") {
		return filename, nil
	}
	return filepath.Join(dbDir, filename), nil
}
