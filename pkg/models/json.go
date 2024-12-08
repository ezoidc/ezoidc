package models

import (
	"encoding/json"
	"io"
)

func JSONEncoder(w io.Writer) *json.Encoder {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e
}
