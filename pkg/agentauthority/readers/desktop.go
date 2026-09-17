package readers

import "encoding/json"

type Extension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func DesktopExtension(data []byte) (Extension, error) {
	var e Extension
	err := json.Unmarshal(data, &e)
	return e, err
}
