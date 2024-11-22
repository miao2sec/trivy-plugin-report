package markdown

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/miao2sec/trivy-plugin-report/internal/utils"
	"strings"
	"testing"
)

func TestExport(t *testing.T) {
	var (
		err    error
		report = &types.Report{}
	)

	type args struct {
		report   *types.Report
		filePath string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "default",
			args: args{
				report:   report,
				filePath: "testdata/kube-hunter.md",
			},
			wantErr: false,
		},
		{
			name: "default",
			args: args{
				report:   report,
				filePath: "testdata/tomcat.md",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.report, err = utils.ReadJSONFromFile(strings.ReplaceAll(tt.args.filePath, ".md", ".json"))
			if err != nil {
				t.Errorf("Failed to read json from file:%v", err)
			}
			if err := Export(tt.args.report, tt.args.filePath); (err != nil) != tt.wantErr {
				t.Errorf("Export() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
