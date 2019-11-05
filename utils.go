package main

func contains(arr []string, str string) bool {
	for _, v := range arr {
	   	if v == str {
		  	return true
	   	}
	}
	return false
}

func index(arr []string, str string) int {
	i := -1
	for k, v := range arr {
		if v == str {
			i = k
			break
		}
	}
	return i
}
