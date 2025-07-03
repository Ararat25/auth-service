package middleware

import (
	"fmt"
	"net/http"
	"time"
)

func Timer(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		defer func() {
			fmt.Printf("Запрос %s, длился %d микросекунд\n", r.RequestURI, time.Since(now).Microseconds())
		}()

		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
