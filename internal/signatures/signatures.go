package signatures

import (
	"fmt"

	"retract/pkg/api"
)

func Heuristics(sections []api.Section, imports []api.ImportFunction, fileEntropy float64, overlay bool) []api.Finding {
	var out []api.Finding
	if fileEntropy >= 7.2 {
		out = append(out, api.Finding{Severity: "high", Category: "packing", Message: fmt.Sprintf("whole-file entropy is high (%.2f)", fileEntropy)})
	}
	if overlay {
		out = append(out, api.Finding{Severity: "medium", Category: "overlay", Message: "overlay data may contain appended payload or certificate data"})
	}
	for _, s := range sections {
		if s.Entropy >= 7.2 {
			out = append(out, api.Finding{Severity: "medium", Category: "packing", Message: fmt.Sprintf("%s has high entropy (%.2f)", s.Name, s.Entropy)})
		}
	}
	for _, imp := range imports {
		for _, cat := range imp.Category {
			if cat == "process injection" || cat == "anti-debugging" {
				out = append(out, api.Finding{Severity: "high", Category: "suspicious_import", Message: imp.DLL + "!" + imp.Name + " categorized as " + cat})
			}
		}
	}
	return out
}
