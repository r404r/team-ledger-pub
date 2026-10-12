package providerapproval

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRequiresCurrentFiniteArtifact(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "approval.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	valid := fmt.Sprintf(`{"version":1,"policy_id":"%s","audience":"manager_followup","endpoint":"https://provider.example/","expires_at":"%s"}`,
		"0199f492-77e9-7c1a-9e0e-b1fcdf3d0061", now.Add(time.Hour).Format(time.RFC3339Nano))
	write(valid)
	approval, err := Load(path, now)
	if err != nil || approval.Endpoint != "https://provider.example" || !approval.Expiry.Equal(now.Add(time.Hour)) {
		t.Fatal("valid finite approval:", approval, err)
	}

	cases := []string{
		fmt.Sprintf(`{"version":1,"policy_id":"0199f492-77e9-7c1a-9e0e-b1fcdf3d0061","audience":"manager_followup","endpoint":"https://provider.example","expires_at":"%s"}`, now.Format(time.RFC3339Nano)),
		fmt.Sprintf(`{"version":1,"policy_id":"0199f492-77e9-7c1a-9e0e-b1fcdf3d0061","audience":"manager_followup","endpoint":"https://provider.example?leak=true","expires_at":"%s"}`, now.Add(time.Hour).Format(time.RFC3339Nano)),
		valid[:len(valid)-1] + `,"unexpected":true}`,
		valid + `{}`,
	}
	for i, body := range cases {
		write(body)
		if _, err = Load(path, now); err == nil {
			t.Fatalf("case %d accepted invalid approval", i)
		}
	}
}
