package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.temporal.io/sdk/activity"
)

type IncidentIoAlert struct {
	Metadata         map[string]string `json:"metadata"`
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	DeduplicationKey string            `json:"deduplication_key"`
	Status           string            `json:"status"`
}

type IncidentIoResponse struct {
	Status           string `json:"status"`
	Message          string `json:"message"`
	DeduplicationKey string `json:"deduplication_key"`
}

type IncidentIoMessageSender struct {
	Sender
}

type IncidentIoMessageSenderImpl struct {
	http   *http.Client
	config IncidentIoMessageSenderConfig
}

type IncidentIoMessageSenderConfig struct {
	URL   string
	Token string
}

func (i *IncidentIoMessageSenderImpl) SendMessage(
	ctx context.Context,
	subject string,
	body string,
	attributes Attributes,
) (*string, error) {
	activityInfo := activity.Info{}
	if activity.IsActivity(ctx) {
		activityInfo = activity.GetInfo(ctx)
	}

	deduplicationString := strings.Join([]string{
		"deployID", attributes.DeploymentUID,
		"subject", subject,
		"runID", activityInfo.WorkflowExecution.RunID,
		"activityName", activityInfo.ActivityType.Name,
	}, " || ")
	h := sha256.New()
	h.Write([]byte(deduplicationString))
	deduplicationHash := hex.EncodeToString(h.Sum(nil))

	alert := IncidentIoAlert{
		Title:            subject,
		Description:      body,
		DeduplicationKey: deduplicationHash,
		Status:           "firing",
		Metadata: map[string]string{
			"alias":          deduplicationHash,
			"deploymentUUID": attributes.DeploymentUID,
			"entity":         attributes.DeploymentUID,
			"level":          string(attributes.Level),
			"tags":           strings.Join(attributes.Tags, ","),
			"type":           attributes.Type,
		},
	}

	alertJSON, err := json.Marshal(alert)
	if err != nil {
		return nil, fmt.Errorf("error serializing alert %w", err)
	}

	req, err := http.NewRequest("POST", i.config.URL, bytes.NewBuffer(alertJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+i.config.Token)

	resp, err := i.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading incident.io response body %w", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("received unexpected response from incident.io. status: %d. body: %s", resp.StatusCode, respBody)
	}

	var incidentResponse IncidentIoResponse
	err = json.Unmarshal(respBody, &incidentResponse)
	if err != nil {
		return nil, fmt.Errorf("error deserializing incident.io response: %w", err)
	}

	return &incidentResponse.Status, nil
}

func NewIncidentIoMessageSender(_ context.Context, config IncidentIoMessageSenderConfig) (Sender, error) {
	client := &http.Client{
		Timeout: time.Second * 5,
	}

	return &IncidentIoMessageSenderImpl{
		config: config,
		http:   client,
	}, nil
}
