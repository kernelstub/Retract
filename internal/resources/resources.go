package resources

import (
	"fmt"

	"retract/internal/formats/pe"
	"retract/pkg/api"
)

type Summary struct {
	Present bool   `json:"present"`
	RVA     string `json:"rva,omitempty"`
	Size    uint32 `json:"size,omitempty"`
	Note    string `json:"note,omitempty"`
}

func SummarizePE(f *pe.File) Summary {
	d, ok := f.Directory(pe.DirResource)
	if !ok {
		return Summary{Present: false}
	}
	return Summary{Present: true, RVA: fmt.Sprintf("0x%x", d.RVA), Size: d.Size, Note: "resource directory detected; raw extraction is written from the directory bytes"}
}

func Findings(s Summary) []api.Finding {
	if !s.Present {
		return nil
	}
	return []api.Finding{{Severity: "info", Category: "resources", Message: "PE resource directory present"}}
}
