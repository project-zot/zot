package common

func Contains(slice []string, item string) bool {
	for _, v := range slice {
		if item == v {
			return true
		}
	}

	return false
}

// func GContains[T string | byte](slice []T, item T) bool {
// 	for _, v := range slice {
// 		if item == v {
// 			return true
// 		}
// 	}

// 	return false
// }

// func GIndex[T string | byte](slice []T, item T) int {
// 	for k, v := range slice {
// 		if item == v {
// 			return k
// 		}
// 	}

// 	return -1
// }

// func GRemoveFrom[T string | []byte](input []T, item T) []T {
// 	var newList []T
// 	for _, v := range input {
// 		if item != v {
// 			newList = append(newList, v)
// 		}
// 	}

// 	return newList
// }

// first match of item in []
func Index(slice []string, item string) int {
	for k, v := range slice {
		if item == v {
			return k
		}
	}

	return -1
}

func RemoveFrom(input []string, item string) []string {
	var newList []string
	for _, v := range input {
		if item != v {
			newList = append(newList, v)
		}
	}

	return newList
}
