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
	"encoding/json"
	"fmt"
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

const (
	daprBaseURLFormat       = "http://localhost:%d/v1.0"
	actorMethodURLFormat    = daprBaseURLFormat + "/actors/%s/%s/%s/%s"
	defaultActorType        = "chaostestactorinvoke" // Actor type must be unique per test app.
	actorTypeEnvName        = "TEST_APP_ACTOR_TYPE"  // To set to change actor type.
	actorIdleTimeout        = "1h"
	actorScanInterval       = "30s"
	drainOngoingCallTimeout = "30s"
	drainRebalancedActors   = true
)

var (
	appPort      = 3000
	daprHTTPPort = 3500
	httpClient   = utils.NewHTTPClient()
	actorType    = getActorType()
)

func init() {
	p := os.Getenv("DAPR_HTTP_PORT")
	if p != "" && p != "0" {
		daprHTTPPort, _ = strconv.Atoi(p)
	}
	p = os.Getenv("PORT")
	if p != "" && p != "0" {
		appPort, _ = strconv.Atoi(p)
	}
}

type daprActor struct {
	actorType string
	id        string
	value     int
}

// represents a response for the APIs in this app.
type actorLogEntry struct {
	Action         string `json:"action,omitempty"`
	ActorType      string `json:"actorType,omitempty"`
	ActorID        string `json:"actorId,omitempty"`
	StartTimestamp int    `json:"startTimestamp,omitempty"`
	EndTimestamp   int    `json:"endTimestamp,omitempty"`
}

type daprConfig struct {
	Entities                   []string `json:"entities,omitempty"`
	ActorIdleTimeout           string   `json:"actorIdleTimeout,omitempty"`
	ActorScanInterval          string   `json:"actorScanInterval,omitempty"`
	DrainOngoingCallTimeout    string   `json:"drainOngoingCallTimeout,omitempty"`
	DrainRebalancedActors      bool     `json:"drainRebalancedActors,omitempty"`
	RemindersStoragePartitions int      `json:"remindersStoragePartitions,omitempty"`
}

// response object from an actor invocation request
type daprActorResponse struct {
	Data     []byte            `json:"data"`
	Metadata map[string]string `json:"metadata"`
}

// requestResponse represents a request or response for the APIs in this app.
type response struct {
	ActorType string `json:"actorType,omitempty"`
	ActorID   string `json:"actorId,omitempty"`
	Method    string `json:"method,omitempty"`
	StartTime int    `json:"start_time,omitempty"`
	EndTime   int    `json:"end_time,omitempty"`
	Message   string `json:"message,omitempty"`
}

var (
	actorLogs           = []actorLogEntry{}
	actorLogsMutex      = &sync.Mutex{}
	registeredActorType = getActorType()
	actors              sync.Map
)

var envOverride sync.Map

func getEnv(envName string) string {
	value, ok := envOverride.Load(envName)
	if ok {
		return fmt.Sprintf("%v", value)
	}

	return os.Getenv(envName)
}

func resetLogs() {
	actorLogsMutex.Lock()
	defer actorLogsMutex.Unlock()

	// Reset the slice without clearing the memory
	actorLogs = actorLogs[:0]
}

func getActorType() string {
	actorType := getEnv(actorTypeEnvName)
	if actorType == "" {
		return defaultActorType
	}

	return actorType
}

func appendLog(actorType string, actorID string, action string, start int) {
	logEntry := actorLogEntry{
		Action:         action,
		ActorType:      actorType,
		ActorID:        actorID,
		StartTimestamp: start,
		EndTimestamp:   epoch(),
	}

	actorLogsMutex.Lock()
	defer actorLogsMutex.Unlock()
	actorLogs = append(actorLogs, logEntry)
}

func getLogs() []actorLogEntry {
	actorLogsMutex.Lock()
	defer actorLogsMutex.Unlock()

	dst := make([]actorLogEntry, len(actorLogs))
	copy(dst, actorLogs)
	return dst
}

func createActorID(actorType string, id string) string {
	return fmt.Sprintf("%s.%s", actorType, id)
}

// indexHandler is the handler for root path
func indexHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("indexHandler is called")

	w.WriteHeader(http.StatusOK)
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing dapr %s request for %s", r.Method, r.URL.RequestURI())
	if r.Method == http.MethodDelete {
		resetLogs()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	log.Print("Responding with logs:")
	json.NewEncoder(io.MultiWriter(w, os.Stdout)).
		Encode(getLogs())
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	daprConfigResponse := daprConfig{
		[]string{actorType},
		actorIdleTimeout,
		actorScanInterval,
		drainOngoingCallTimeout,
		drainRebalancedActors,
		0,
	}

	log.Printf("Processing dapr request for %s, responding with %#v", r.URL.RequestURI(), daprConfigResponse)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(daprConfigResponse)
}

func actorMethodHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing actor method request for %s", r.URL.RequestURI())

	start := epoch()

	actorType := mux.Vars(r)["actorType"]
	id := mux.Vars(r)["id"]
	method := mux.Vars(r)["method"]

	actorID := createActorID(actorType, id)
	log.Printf("storing, actorID is %s\n", actorID)

	actors.Store(actorID, daprActor{
		actorType: actorType,
		id:        actorID,
		value:     epoch(),
	})

	hostname, err := os.Hostname()
	var data []byte
	if method == "hostname" {
		data = []byte(hostname)
	} else {
		data, err = json.Marshal(response{
			actorType,
			id,
			method,
			start,
			epoch(),
			"",
		})
	}

	if err != nil {
		fmt.Printf("Error: %v", err.Error()) //nolint:forbidigo
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	appendLog(actorType, id, method, start)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(daprActorResponse{
		Data: data,
	})
}

func deactivateActorHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing %s actor request for %s", r.Method, r.URL.RequestURI())

	start := epoch()

	actorType := mux.Vars(r)["actorType"]
	id := mux.Vars(r)["id"]

	if actorType != registeredActorType {
		log.Printf("Unknown actor type: %s", actorType)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	actorID := createActorID(actorType, id)
	action := ""

	_, ok := actors.Load(actorID)
	if ok && r.Method == "DELETE" {
		action = "deactivation"
		actors.Delete(actorID)
	}

	appendLog(actorType, id, action, start)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// calls Dapr's Actor method: simulating actor client call.
func testCallActorHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing %s test request for %s", r.Method, r.URL.RequestURI())

	actorType := mux.Vars(r)["actorType"]
	id := mux.Vars(r)["id"]
	callType := mux.Vars(r)["callType"]
	method := mux.Vars(r)["method"]

	url := fmt.Sprintf(actorMethodURLFormat, daprHTTPPort, actorType, id, callType, method)

	log.Printf("Invoking: %s %s\n", r.Method, url)
	expectedHTTPCode := 200

	body, err := httpCall(r.Method, url, nil, expectedHTTPCode)
	if err != nil {
		log.Printf("Could not read actor's test response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(body) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	var response daprActorResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Printf("Could not parse actor's test response: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(response.Data)
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

// epoch returns the current unix epoch timestamp
func epoch() int {
	return int(time.Now().UnixMilli())
}

// appRouter initializes restful api router
func appRouter() http.Handler {
	router := mux.NewRouter().StrictSlash(true)

	// Log requests and their processing time
	router.Use(utils.LoggerMiddleware)

	router.HandleFunc("/", indexHandler).Methods("GET")
	if actorType != "" {
		router.HandleFunc("/dapr/config", configHandler).Methods("GET")
	}

	// To simulate actor client.
	router.HandleFunc("/call/{actorType}/{id}/{callType}/{method}", testCallActorHandler).Methods("POST", "DELETE", "PATCH", "GET")

	router.HandleFunc("/actors/{actorType}/{id}/method/{method}", actorMethodHandler).Methods("PUT")

	router.HandleFunc("/actors/{actorType}/{id}", deactivateActorHandler).Methods("POST", "DELETE")

	router.HandleFunc("/test/logs", logsHandler).Methods("GET", "DELETE")
	router.HandleFunc("/test/metadata", testCallMetadataHandler).Methods("GET")
	router.HandleFunc("/test/env/{envName}", testEnvHandler).Methods("GET", "POST")
	router.HandleFunc("/test/shutdown", shutdownHandler).Methods("POST")
	router.HandleFunc("/test/shutdownsidecar", shutdownSidecarHandler).Methods("POST")
	router.HandleFunc("/test/sidecarHealthz", testCallSidecarHealthzHandler).Methods("GET")

	router.HandleFunc("/healthz", healthzHandler).Methods("GET")

	return router
}

func main() {
	log.Printf("Actor App - listening on http://localhost:%d", appPort)
	utils.StartServer(appPort, appRouter, true, false)
}
