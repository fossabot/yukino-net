package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/xpy123993/router/util"
)

var noCacheHeaders = map[string]string{
	"Expires":         time.Unix(0, 0).Format(time.RFC1123),
	"Cache-Control":   "no-cache, private, max-age=0",
	"Pragma":          "no-cache",
	"X-Accel-Expires": "0",
}

var etagHeaders = []string{
	"ETag",
	"If-Modified-Since",
	"If-Match",
	"If-None-Match",
	"If-Range",
	"If-Unmodified-Since",
}

func NoCache(h http.Handler) http.Handler {
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

func main() {
	configFile := flag.String("config", "config.json", "The location of the config file.")
	channel := flag.String("c", "file", "channel to serve")
	directory := flag.String("d", ".", "the directory of static file to host")
	flag.Parse()

	listener, err := util.CreateListenerFromConfig(*configFile, *channel)
	if err != nil {
		log.Fatalf("failed to listen on channel: %v", err)
	}
	http.Handle("/", NoCache(http.FileServer(http.Dir(*directory))))

	log.Printf("Serving %s on Channel: %s\n", *directory, *channel)
	log.Fatal(http.Serve(listener, nil))
}
