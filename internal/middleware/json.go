package middleware

import "net/http"

func JsonHeader(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
