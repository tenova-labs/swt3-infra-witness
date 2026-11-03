package extract

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// ocsfAPIActivity maps OCSF Class 6003 (API Activity) fields.
// Accepts pre-normalized events from any SIEM (Datadog, Splunk, Security Lake).
type ocsfAPIActivity struct {
	ClassUID  int    `json:"class_uid"`
	ClassName string `json:"class_name"`
	API       struct {
		Operation string `json:"operation"`
	} `json:"api"`
	Actor struct {
		User struct {
			UID  string `json:"uid"`
			Name string `json:"name"`
		} `json:"user"`
	} `json:"actor"`
	Cloud struct {
		Region   string `json:"region"`
		Resource struct {
			UID  string `json:"uid"`
			Name string `json:"name"`
		} `json:"resource"`
	} `json:"cloud"`
	DstEndpoint struct {
		UID string `json:"uid"`
	} `json:"dst_endpoint"`
	Time       interface{} `json:"time"`    // string or number
	TimeDt     interface{} `json:"time_dt"` // epoch ms or ISO string
	Status     string      `json:"status"`
	StatusCode int         `json:"status_code"`
	StatusID   int         `json:"status_id"` // OCSF status: 1=Success, 2=Failure
	ActivityID int         `json:"activity_id"`
	Metadata   struct {
		UID string `json:"uid"`
	} `json:"metadata"`
}

// ocsfEnvelope wraps events from SIEM export.
type ocsfEnvelope struct {
	Events []ocsfAPIActivity `json:"events"`
}

// ParseOCSF extracts canonical events from OCSF Class 6003 JSON.
// Accepts single event, {"events": [...]}, or bare array.
func ParseOCSF(data []byte) ([]CanonicalEvent, error) {
	// Try events envelope
	var envelope ocsfEnvelope
	if err := json.Unmarshal(data, &envelope); err == nil && len(envelope.Events) > 0 {
		return convertOCSFEvents(envelope.Events)
	}

	// Try array
	var events []ocsfAPIActivity
	if err := json.Unmarshal(data, &events); err == nil && len(events) > 0 {
		return convertOCSFEvents(events)
	}

	// Try single event
	var single ocsfAPIActivity
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("invalid OCSF JSON: %w", err)
	}
	if single.API.Operation == "" {
		return nil, fmt.Errorf("invalid OCSF event: missing api.operation")
	}
	return convertOCSFEvents([]ocsfAPIActivity{single})
}

func convertOCSFEvents(events []ocsfAPIActivity) ([]CanonicalEvent, error) {
	result := make([]CanonicalEvent, 0, len(events))
	for i, e := range events {
		if e.API.Operation == "" {
			return nil, fmt.Errorf("event %d: missing api.operation", i)
		}

		// Actor: prefer uid, fallback to name
		actor := e.Actor.User.UID
		if actor == "" {
			actor = e.Actor.User.Name
		}

		// Resource: prefer cloud.resource.uid, fallback to dst_endpoint.uid
		resource := e.Cloud.Resource.UID
		if resource == "" {
			resource = e.Cloud.Resource.Name
		}
		if resource == "" {
			resource = e.DstEndpoint.UID
		}

		// Time: prefer time_dt, fallback to time
		timeStr := resolveOCSFTime(e.TimeDt)
		if timeStr == "" {
			timeStr = resolveOCSFTime(e.Time)
		}

		// Status
		status := e.Status
		if status == "" {
			if e.StatusID == 1 || e.StatusCode == 0 {
				status = "Success"
			} else {
				status = fmt.Sprintf("ERROR_%d", e.StatusCode)
			}
		}

		// Activity type: use OCSF activity_id directly if valid (1-4), else classify
		actType := e.ActivityID
		if actType < 1 || actType > 4 {
			actType = classifyActivity(e.API.Operation)
		}

		result = append(result, CanonicalEvent{
			Operation:    e.API.Operation,
			Actor:        actor,
			Resource:     resource,
			Time:         timeStr,
			Status:       status,
			Region:       e.Cloud.Region,
			ActivityType: actType,
			EventID:      e.Metadata.UID,
		})
	}
	return result, nil
}

// resolveOCSFTime handles OCSF time fields that can be string (ISO) or number (epoch ms).
func resolveOCSFTime(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		// Epoch milliseconds -- format as ISO string would be lossy, keep as string repr
		return strconv.FormatInt(int64(t), 10)
	}
	return fmt.Sprintf("%v", v)
}
