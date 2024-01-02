/*
Copyright 2021 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dapr/dapr/tests/apps/utils"

	"github.com/gorilla/mux"
)

var (
	appPort = 3000
)

func init() {
	p := os.Getenv("PORT")
	if p != "" && p != "0" {
		appPort, _ = strconv.Atoi(p)
	}
}

// represents an error message received from an app.
type errorEntry struct {
	Message   string `json:"message,omitempty"`
	AppID     string `json:"appId,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

var (
	errors      = []errorEntry{}
	errorsMutex = &sync.Mutex{}
)

func resetErrors() {
	errorsMutex.Lock()
	defer errorsMutex.Unlock()

	// Reset the slice without clearing the memory
	errors = errors[:0]
}

func appendError(appID string, timestamp int64, message string) {
	record := errorEntry{
		AppID:     appID,
		Timestamp: timestamp,
		Message:   message,
	}

	errorsMutex.Lock()
	defer errorsMutex.Unlock()
	errors = append(errors, record)
}

func getErrors() []errorEntry {
	errorsMutex.Lock()
	defer errorsMutex.Unlock()

	dst := make([]errorEntry, len(errors))
	copy(dst, errors)
	return dst
}

// indexHandler is the handler for root path
func indexHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("indexHandler is called")

	w.WriteHeader(http.StatusOK)
}

func errorsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing dapr %s request for %s", r.Method, r.URL.RequestURI())
	if r.Method == http.MethodDelete {
		resetErrors()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	log.Print("Responding with logs:")
	json.NewEncoder(io.MultiWriter(w, os.Stdout)).
		Encode(getErrors())
}

func appendErrorHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing append error request for %s", r.URL.RequestURI())
	defer r.Body.Close()

	timestamp := epoch()

	appID := mux.Vars(r)["appID"]
	originalTimestamp := r.URL.Query().Get("timestamp")
	if originalTimestamp != "" {
		if ts, err := strconv.ParseInt(originalTimestamp, 10, 64); err == nil {
			timestamp = ts
		}
	}
	body, err := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/text")

	if err != nil {
		log.Printf("Could not read request body: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	appendError(appID, timestamp, string(body))
	w.WriteHeader(http.StatusOK)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

// epoch returns the current unix epoch timestamp
func epoch() int64 {
	return time.Now().UnixMilli()
}

// appRouter initializes restful api router
func appRouter() http.Handler {
	router := mux.NewRouter().StrictSlash(true)

	// Log requests and their processing time
	router.Use(utils.LoggerMiddleware)

	router.HandleFunc("/", indexHandler).Methods("GET")

	router.HandleFunc("/errors/{appID}", appendErrorHandler).Methods("POST")
	router.HandleFunc("/errors", errorsHandler).Methods("GET", "DELETE")
	router.HandleFunc("/healthz", healthzHandler).Methods("GET")

	return router
}

func main() {
	log.Printf("Actor App - listening on http://localhost:%d", appPort)
	utils.StartServer(appPort, appRouter, true, false)
}
