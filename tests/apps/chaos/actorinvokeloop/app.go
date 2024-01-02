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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/dapr/dapr/tests/apps/utils"
	"github.com/google/uuid"

	"github.com/gorilla/mux"
)

const (
	daprBaseURLFormat    = "http://localhost:%d/v1.0"
	actorMethodURLFormat = daprBaseURLFormat + "/actors/%s/%s/%s/%s"
	appendErrorURLFormat = daprBaseURLFormat + "/invoke/%s/method/errors/%s"
	defaultActorType     = "chaostestactorinvoke" // Actor type must be unique per test app.
	actorTypeEnvName     = "TEST_APP_ACTOR_TYPE"  // To set to change actor type.
)

var (
	appID               = "actorinvokeloop"
	appPort             = 3000
	daprHTTPPort        = 3500
	httpClient          = utils.NewHTTPClient()
	actorType           = getActorType()
	errorCollectorAppID = ""

	actorInvokeLoopInternalMilliseconds = 0
)

// represents the stats for the test
type actorInvokeStats struct {
	Count      int `json:"count"`
	ErrorCount int `json:"errorCount"`
}

func init() {
	p := os.Getenv("DAPR_HTTP_PORT")
	if p != "" && p != "0" {
		daprHTTPPort, _ = strconv.Atoi(p)
	}
	p = os.Getenv("PORT")
	if p != "" && p != "0" {
		appPort, _ = strconv.Atoi(p)
	}
	p = os.Getenv("TEST_INVOKE_ACTOR_LOOP_INTERVAL_MS")
	if p != "" && p != "0" {
		actorInvokeLoopInternalMilliseconds, _ = strconv.Atoi(p)
	}
	p = os.Getenv("TEST_ERROR_COLLECTOR_APP_ID")
	if p != "" {
		errorCollectorAppID = p
	}
	p = os.Getenv("TEST_APP_ID")
	if p != "" {
		appID = p
	}
}

var (
	actorInvokeLoopStats      = actorInvokeStats{}
	actorInvokeLoopStatsMutex = &sync.Mutex{}
)

var envOverride sync.Map

func getEnv(envName string) string {
	value, ok := envOverride.Load(envName)
	if ok {
		return fmt.Sprintf("%v", value)
	}

	return os.Getenv(envName)
}

func getActorType() string {
	actorType := getEnv(actorTypeEnvName)
	if actorType == "" {
		return defaultActorType
	}

	return actorType
}

// indexHandler is the handler for root path
func indexHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("indexHandler is called")

	w.WriteHeader(http.StatusOK)
}

func testCallMetadataHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing %s test request for %s", r.Method, r.URL.RequestURI())

	metadataURL := fmt.Sprintf(daprBaseURLFormat+"/metadata", daprHTTPPort)
	body, err := httpCall(r.Method, metadataURL, nil, 200)
	if err != nil {
		log.Printf("Could not read metadata response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(body)
}

func testCallSidecarHealthzHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing %s test request for %s", r.Method, r.URL.RequestURI())

	healthzURL := fmt.Sprintf(daprBaseURLFormat+"/healthz", daprHTTPPort)
	body, err := httpCall(r.Method, healthzURL, nil, 200)
	if err != nil {
		log.Printf("Could not read healthz response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(body)
}

func shutdownHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing %s test request for %s", r.Method, r.URL.RequestURI())

	shutdownURL := fmt.Sprintf(daprBaseURLFormat+"/shutdown", daprHTTPPort)
	_, err := httpCall(r.Method, shutdownURL, nil, 204)
	if err != nil {
		log.Printf("Could not shutdown sidecar: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	go func() {
		time.Sleep(1 * time.Second)
		log.Fatal("simulating fatal shutdown")
	}()
}

func shutdownSidecarHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing %s test request for %s", r.Method, r.URL.RequestURI())

	shutdownURL := fmt.Sprintf(daprBaseURLFormat+"/shutdown", daprHTTPPort)
	_, err := httpCall(r.Method, shutdownURL, nil, 204)
	if err != nil {
		log.Printf("Could not shutdown sidecar: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func testEnvHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing %s test request for %s", r.Method, r.URL.RequestURI())

	envName := mux.Vars(r)["envName"]
	if r.Method == http.MethodGet {
		envValue := getEnv(envName)

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(envValue))
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			log.Printf("Could not read config env value: %s", err.Error())
			return
		}

		envOverride.Store(envName, string(body))
	}
}

func httpCall(method string, url string, requestBody interface{}, expectedHTTPStatusCode int) ([]byte, error) {
	var body []byte
	var err error

	if requestBody != nil {
		body, err = json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != expectedHTTPStatusCode {
		var errBody []byte
		errBody, err = io.ReadAll(res.Body)
		if err == nil {
			return nil, fmt.Errorf("expected http status %d, received %d, payload ='%s'", expectedHTTPStatusCode, res.StatusCode, string(errBody)) //nolint:stylecheck
		}

		return nil, fmt.Errorf("expected http status %d, received %d", expectedHTTPStatusCode, res.StatusCode) //nolint:stylecheck
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return resBody, nil
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing dapr %s request for %s", r.Method, r.URL.RequestURI())
	actorInvokeLoopStatsMutex.Lock()
	defer actorInvokeLoopStatsMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodDelete {
		actorInvokeLoopStats = actorInvokeStats{}
		return
	}

	json.NewEncoder(io.MultiWriter(w, os.Stdout)).
		Encode(actorInvokeLoopStats)
}

func invokeActorLoop(ctx context.Context) {
	if actorInvokeLoopInternalMilliseconds <= 0 {
		return
	}

	log.Printf("Starting loop to invoke actor every %d milliseconds ... ", actorInvokeLoopInternalMilliseconds)

	// Create a ticker that ticks every x ms
	ticker := time.NewTicker(time.Duration(actorInvokeLoopInternalMilliseconds) * time.Millisecond)

	// Infinite loop to make an HTTP call every second
	for {
		select {
		case <-ticker.C:
			// URL to make the HTTP call to
			actorId := uuid.NewString()
			url := fmt.Sprintf(actorMethodURLFormat, daprHTTPPort, actorType, actorId, "method", "echo")
			_, err := httpCall("POST", url, "{}", 200)

			actorInvokeLoopStatsMutex.Lock()

			actorInvokeLoopStats.Count += 1
			if err != nil {
				actorInvokeLoopStats.ErrorCount += 1
			}
			actorInvokeLoopStatsMutex.Unlock()

			if err != nil {
				log.Printf("Error invoking actor: %s - %s", url, err)
				if errorCollectorAppID != "" {
					collectorURL := fmt.Sprintf(appendErrorURLFormat, daprHTTPPort, errorCollectorAppID, appID)
					_, collectorErr := httpCall("POST", collectorURL, err.Error(), 200)
					if collectorErr != nil {
						log.Printf("Could not append to error collector: %s", collectorErr)
					}
				}
			}
		case <-ctx.Done():
			// Context is canceled, stop the loop
			ticker.Stop()
			return
		}
	}
}

// appRouter initializes restful api router
func appRouter() http.Handler {
	router := mux.NewRouter().StrictSlash(true)

	// Log requests and their processing time
	router.Use(utils.LoggerMiddleware)

	router.HandleFunc("/", indexHandler).Methods("GET")
	router.HandleFunc("/test/metadata", testCallMetadataHandler).Methods("GET")
	router.HandleFunc("/test/env/{envName}", testEnvHandler).Methods("GET", "POST")
	router.HandleFunc("/test/shutdown", shutdownHandler).Methods("POST")
	router.HandleFunc("/test/shutdownsidecar", shutdownSidecarHandler).Methods("POST")
	router.HandleFunc("/test/sidecarHealthz", testCallSidecarHealthzHandler).Methods("GET")

	router.HandleFunc("/test/stats", statsHandler).Methods("GET", "DELETE")

	router.HandleFunc("/healthz", healthzHandler).Methods("GET")

	return router
}

func main() {
	log.Printf("Actor App - listening on http://localhost:%d", appPort)

	// Create a context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Handle interrupt signal to stop gracefully
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Println("\nReceived interrupt signal. Stopping gracefully...")
		cancel()
		os.Exit(0)
	}()

	go invokeActorLoop(ctx)

	utils.StartServer(appPort, appRouter, true, false)
}
