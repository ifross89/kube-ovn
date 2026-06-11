package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubeovn/kube-ovn/pkg/util"
)

func TestPodCreateHookValidatesDynamicIPFamily(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	hook := &ValidatingHook{
		decoder: admission.NewDecoder(scheme),
		cache:   &mockCache{objects: map[string]runtime.Object{}},
	}

	tests := []struct {
		name        string
		annotations map[string]string
		allowed     bool
		errorText   string
	}{
		{
			name:        "valid IPv4 restriction",
			annotations: map[string]string{util.IPFamilyAnnotation: util.IPFamilyIPv4},
			allowed:     true,
		},
		{
			name:        "valid IPv6 restriction",
			annotations: map[string]string{util.IPFamilyAnnotation: util.IPFamilyIPv6},
			allowed:     true,
		},
		{
			name:        "invalid restriction",
			annotations: map[string]string{util.IPFamilyAnnotation: "dual"},
			errorText:   `"dual" is not a valid ` + util.IPFamilyAnnotation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "pod",
					Namespace:   "default",
					Annotations: tt.annotations,
				},
			}
			raw, err := json.Marshal(pod)
			require.NoError(t, err)
			request := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object:    runtime.RawExtension{Raw: raw},
			}}

			response := hook.PodCreateHook(context.Background(), request)
			require.Equal(t, tt.allowed, response.Allowed)
			if tt.errorText != "" {
				require.Contains(t, response.Result.Message, tt.errorText)
			}
		})
	}
}

func TestCheckIPAddressFamilyUniqueness(t *testing.T) {
	tests := []struct {
		name      string
		ipAddress string
		wantErr   string
	}{
		{
			name:      "single IPv4",
			ipAddress: "10.0.0.1",
		},
		{
			name:      "single IPv6",
			ipAddress: "fd00::1",
		},
		{
			name:      "dual-stack v4 first",
			ipAddress: "10.0.0.1,fd00::1",
		},
		{
			name:      "dual-stack v6 first",
			ipAddress: "fd00::1,10.0.0.1",
		},
		{
			name:      "dual-stack with spaces",
			ipAddress: "10.0.0.1, fd00::1",
		},
		{
			name:      "single IPv4 with CIDR suffix",
			ipAddress: "10.0.0.1/24",
		},
		{
			name:      "dual-stack with CIDR suffix",
			ipAddress: "10.0.0.1/24,fd00::1/64",
		},
		{
			name:      "two IPv4 addresses rejected",
			ipAddress: "10.0.0.1,10.0.0.2",
			wantErr:   `multiple IPv4 addresses in ip_address annotation "10.0.0.1,10.0.0.2"`,
		},
		{
			name:      "two IPv6 addresses rejected",
			ipAddress: "fd00::1,fd00::2",
			wantErr:   `multiple IPv6 addresses in ip_address annotation "fd00::1,fd00::2"`,
		},
		{
			name:      "v4 + v4 + v6 rejected on v4 count",
			ipAddress: "10.0.0.1,10.0.0.2,fd00::1",
			wantErr:   `multiple IPv4 addresses in ip_address annotation "10.0.0.1,10.0.0.2,fd00::1"`,
		},
		{
			name:      "v4 + v6 + v6 rejected on v6 count",
			ipAddress: "10.0.0.1,fd00::1,fd00::2",
			wantErr:   `multiple IPv6 addresses in ip_address annotation "10.0.0.1,fd00::1,fd00::2"`,
		},
		{
			// Defer reporting to checkIPConflict for consistent error wording.
			name:      "invalid IP is left for checkIPConflict",
			ipAddress: "10.0.0.1,not-an-ip",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkIPAddressFamilyUniqueness(tc.ipAddress)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}
