package helper

func Filter[T comparable](values []T, fn func(T) bool) []T {
	res := make([]T, 0)
	for _, v := range values {
		if fn(v) {
			res = append(res, v)
		}
	}
	return res
}

func Map[T comparable, S comparable](values []T, fn func(T) S) []S {
	res := make([]S, len(values))
	for i, v := range values {
		res[i] = fn(v)
	}
	return res
}

func Includes[T comparable](values []T, fn func(T) bool) bool {
	for _, v := range values {
		if fn(v) {
			return true
		}
	}
	return false
}
