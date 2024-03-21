/*
Copyright 2024 The Dapr Authors
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

package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"google.golang.org/protobuf/types/known/emptypb"

	apierrors "github.com/dapr/dapr/pkg/api/errors"
	"github.com/dapr/dapr/pkg/api/http/endpoints"
	runtimev1pb "github.com/dapr/dapr/pkg/proto/runtime/v1"
)

var endpointGroupSchedulerV1Alpha1 = &endpoints.EndpointGroup{
	Name:                 endpoints.EndpointGroupScheduler,
	Version:              endpoints.EndpointGroupVersion1alpha1,
	AppendSpanAttributes: nil,
}

func (a *api) constructSchedulerEndpoints() []endpoints.Endpoint {
	return []endpoints.Endpoint{
		{
			Methods: []string{http.MethodPost},
			Route:   "job/schedule/{name}",
			Version: apiVersionV1,
			Group:   endpointGroupSchedulerV1Alpha1,
			Handler: a.onCreateScheduleHandler(),
			Settings: endpoints.EndpointSettings{
				Name: "ScheduleJob",
			},
		},
		{
			Methods: []string{http.MethodDelete},
			Route:   "job/{name}",
			Version: apiVersionV1,
			Group:   endpointGroupSchedulerV1Alpha1,
			Handler: a.onDeleteJobHandler(),
			Settings: endpoints.EndpointSettings{
				Name: "DeleteJob",
			},
		},
	}
}

func (a *api) onCreateScheduleHandler() http.HandlerFunc {
	return UniversalHTTPHandler(
		a.universal.ScheduleJob,
		UniversalHTTPHandlerOpts[*runtimev1pb.ScheduleJobRequest, *emptypb.Empty]{
			InModifier: func(r *http.Request, in *runtimev1pb.ScheduleJobRequest) (*runtimev1pb.ScheduleJobRequest, error) {
				// Users should set the name in the url, and not in the url and body
				if (chi.URLParam(r, nameParam) == "") || (in.GetJob().GetName() != "") {
					return nil, apierrors.SchedulerURLName(map[string]string{"app_id": a.universal.AppID()})
				}

				job := &runtimev1pb.Job{
					Name:     chi.URLParam(r, nameParam),
					Schedule: in.GetJob().GetSchedule(),
					Data:     in.GetJob().GetData(),
					Repeats:  in.GetJob().GetRepeats(),
					DueTime:  in.GetJob().GetDueTime(),
					Ttl:      in.GetJob().GetTtl(),
				}

				in.Job = job
				return in, nil
			},
			OutModifier: func(out *emptypb.Empty) (any, error) {
				// Nullify the response so status code is 204
				return nil, nil // empty body
			},
		},
	)
}

func (a *api) onDeleteJobHandler() http.HandlerFunc {
	return UniversalHTTPHandler(
		a.universal.DeleteJob,
		UniversalHTTPHandlerOpts[*runtimev1pb.DeleteJobRequest, *emptypb.Empty]{
			SkipInputBody: true,
			InModifier: func(r *http.Request, in *runtimev1pb.DeleteJobRequest) (*runtimev1pb.DeleteJobRequest, error) {
				name := chi.URLParam(r, "name")
				in.Name = name
				return in, nil
			},
			OutModifier: func(out *emptypb.Empty) (any, error) {
				// Nullify the response so status code is 204
				return nil, nil // empty body
			},
		},
	)
}
