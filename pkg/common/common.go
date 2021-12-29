package common

func Contains(slice []string, item string) bool {
	for _, v := range slice {
		if item == v {
			return true
		}
	}

	return false
}
