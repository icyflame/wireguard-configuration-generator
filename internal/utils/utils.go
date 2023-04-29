package utils

// IsUnique ...
func IsUnique(a []string) bool {
	id := make(map[string]bool)
	for _, val := range a {
		if id[val] {
			return false
		}

		id[val] = true
	}

	return true
}
