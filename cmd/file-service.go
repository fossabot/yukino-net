package cmd

import (
	"log"
	"net/http"
	"time"

	"github.com/xpy123993/yukino-net/libraries/util"
)

func noCacheHandler(h http.Handler, etagHeaders []string, noCacheHeaders map[string]string) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		for _, v := range etagHeaders {
			if r.Header.Get(v) != "" {
				r.Header.Del(v)
			}
		}
		for k, v := range noCacheHeaders {
			w.Header().Set(k, v)
		}

		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func StartHTTPFileService(ConfigFile, Channel, Directory string) error {
	listener, err := util.CreateListenerFromConfig(ConfigFile, Channel)
	if err != nil {
		return err
	}
	http.Handle("/", noCacheHandler(http.FileServer(http.Dir(Directory)), []string{
		"ETag",
		"If-Modified-Since",
		"If-Match",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
	}, map[string]string{
		"Expires":         time.Unix(0, 0).Format(time.RFC1123),
		"Cache-Control":   "no-cache, private, max-age=0",
		"Pragma":          "no-cache",
		"X-Accel-Expires": "0",
	}))

	log.Printf("Serving %s on Channel: %s\n", Directory, Channel)
	return http.Serve(listener, nil)
}
