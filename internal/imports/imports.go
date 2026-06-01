package imports

import "retract/internal/formats/pe"

func Categorize(name string) []string {
	return pe.CategorizeImport(name)
}
