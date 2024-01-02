//go:build chaos
// +build chaos

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

package actor_invoke_with_sidecar_restarts_chaos

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dapr/dapr/tests/e2e/utils"
	kube "github.com/dapr/dapr/tests/platforms/kubernetes"
	"github.com/dapr/dapr/tests/runner"
	"github.com/stretchr/testify/require"
)

const (
	numHealthChecks          = 60 // Number of times to check for endpoint health per app.
	serviceApplicationName   = "chaos-actor-invoke-service"
	serviceReplicaCount      = 20
	clientApplicationName    = "chaos-actor-invoke-client"
	clientReplicaCount       = 5
	collectorApplicationName = "chaos-error-collector"

	numRestarts              = 20                                     // Number of times to restart sidecar before testing invocation.
	numInvocationValidations = 10                                     // Number of different actor IDs to be invoked to validate health of actors in the end.
	actorInvokeURLFormat     = "%s/call/chaostestactorinvoke/%s/echo" // URL to invoke a Dapr's actor method in another app.
	shutdownSidecarURLFormat = "%s/test/shutdownsidecar"              // URL to shutdown the sidecar.
	metadataURLFormat        = "%s/test/metadata"                     // URL to fetch sidecar metadata.
)

var tr *runner.TestRunner

func TestMain(m *testing.M) {
	utils.InitHTTPClient(false)
	utils.SetupLogs("chaos_actor_invoke")

	testApps := []kube.AppDescription{
		{
			AppName:        collectorApplicationName,
			DaprEnabled:    true,
			ImageName:      "chaos-errorcollector",
			Replicas:       1,
			IngressEnabled: true,
			MetricsEnabled: true,
			AppPort:        3000,
			DaprCPULimit:   "2.0",
			DaprCPURequest: "0.1",
			AppCPULimit:    "2.0",
			AppCPURequest:  "0.1",
			Labels: map[string]string{
				"daprtest": serviceApplicationName,
			},
		},
		{
			AppName:        serviceApplicationName,
			DaprEnabled:    true,
			ImageName:      "chaos-actorinvoke",
			Replicas:       serviceReplicaCount,
			IngressEnabled: false,
			MetricsEnabled: true,
			AppPort:        3000,
			DaprCPULimit:   "2.0",
			DaprCPURequest: "0.1",
			AppCPULimit:    "2.0",
			AppCPURequest:  "0.1",
			Labels: map[string]string{
				"daprtest": serviceApplicationName,
			},
		},
		{
			AppName:        clientApplicationName,
			DaprEnabled:    true,
			ImageName:      "chaos-actorinvokeloop",
			Replicas:       10,
			IngressEnabled: true,
			MetricsEnabled: true,
			AppPort:        3000,
			DaprCPULimit:   "2.0",
			DaprCPURequest: "0.1",
			AppCPULimit:    "2.0",
			AppCPURequest:  "0.1",
			Labels: map[string]string{
				"daprtest": clientApplicationName,
			},
			AppEnv: map[string]string{
				"TEST_INVOKE_ACTOR_LOOP_INTERVAL_MS": "100",
				"TEST_ERROR_COLLECTOR_APP_ID":        collectorApplicationName,
				"TEST_APP_ID":                        clientApplicationName,
			},
		},
	}

	tr = runner.NewTestRunner("actorinvokewithsidecarrestart", testApps, nil, nil)
	os.Exit(tr.Start(m))
}

// represents the stats for the test in one app instance
type actorInvokeStats struct {
	Count      int `json:"count,omitempty"`
	ErrorCount int `json:"errorCount,omitempty"`
}

// represents an error message received from any of the app instances.
type errorEntry struct {
	Message   string `json:"message,omitempty"`
	AppID     string `json:"appId,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

func TestActorInvokeWithSidecarRestart(t *testing.T) {
	// First, check if invocations are working.
	clientAppURL := tr.Platform.AcquireAppExternalURL(clientApplicationName)
	require.NotEmpty(t, clientAppURL, "client app external URL must not be empty")
	collectorAppURL := tr.Platform.AcquireAppExternalURL(collectorApplicationName)
	require.NotEmpty(t, collectorAppURL, "collector app external URL must not be empty")

	// Wait for health
	_, err := utils.HTTPGetNTimes(clientAppURL+"/healthz", numHealthChecks)
	require.NoError(t, err)
	_, err = utils.HTTPGetNTimes(collectorAppURL+"/healthz", numHealthChecks)
	require.NoError(t, err)

	// Reset the stats first because the client can fail in the beginning due to timing of pods being created.
	t.Logf("DELETE call for client app url: %s", clientAppURL+"/test/stats")
	_, err = utils.HTTPDelete(clientAppURL + "/test/stats")
	require.NoError(t, err)
	t.Logf("DELETE call for collector app url: %s", collectorAppURL+"/errors")
	_, err = utils.HTTPDelete(collectorAppURL + "/errors")
	require.NoError(t, err)

	// Let the client run for a few seconds before making assertions.
	time.Sleep(10 * time.Second)

	previousStats := actorInvokeStats{}
	// First, observe one of the client instances.
	for iteration := 0; iteration < numInvocationValidations; iteration++ {
		t.Logf("client app url: %s", clientAppURL+"/test/stats")
		body, err := utils.HTTPGetNTimes(clientAppURL+"/test/stats", numHealthChecks)
		require.NoError(t, err)

		stats := actorInvokeStats{}
		err = json.Unmarshal(body, &stats)
		require.NoError(t, err)

		require.Greater(t, stats.Count, previousStats.Count)
		require.Zero(t, stats.ErrorCount)
		previousStats = stats

		time.Sleep(10 * time.Second)
	}

	// Then, confirm there are no errors globally:
	body, err := utils.HTTPGetNTimes(collectorAppURL+"/errors", numHealthChecks)
	require.NoError(t, err)
	globalErrors := []errorEntry{}
	err = json.Unmarshal(body, &globalErrors)
	require.NoError(t, err)
	globalErrorCount := len(globalErrors)
	if globalErrorCount > 0 {
		require.Failf(t, "There are %s errors collected in the cluster, last: %s", strconv.Itoa(globalErrorCount), globalErrors[globalErrorCount-1].Message)
	}

	// Now, restart apps a few times, except error collector app.
	for iteration := 0; iteration < numRestarts; iteration++ {
		err := tr.Platform.RestartApps(serviceApplicationName, clientApplicationName)
		require.NoError(t, err)

		// Sleep is required, otherwise one of the restarts will fail:
		// "Operation cannot be fulfilled on deployments.apps "chaos-actor-invoke-service": the object has been modified; please apply your changes to the latest version and try again"
		time.Sleep(10 * time.Second)
	}

	t.Logf("restarted sidecar multiple times already, now running validation ...")

	// Now, validate that the invocations continued without any errors.
	body, err = utils.HTTPGetNTimes(collectorAppURL+"/errors", numHealthChecks)
	require.NoError(t, err)
	globalErrors = []errorEntry{}
	err = json.Unmarshal(body, &globalErrors)
	require.NoError(t, err)
	globalErrorCount = len(globalErrors)
	noRouteToHostErrorCount := 0
	for _, globalError := range globalErrors {
		if strings.Contains(globalError.Message, "no route to host") {
			noRouteToHostErrorCount += 1
		}
	}

	t.Logf("found %d errors total, %d instances of 'no route to host'", globalErrorCount, noRouteToHostErrorCount)

	if noRouteToHostErrorCount > 0 {
		require.Failf(t, "Found 'no route to host' errors", "There are %s instances of 'no route to host'", strconv.Itoa(noRouteToHostErrorCount))
	}
}
