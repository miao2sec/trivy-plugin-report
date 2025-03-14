package markdown

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/miao2sec/trivy-plugin-report/utils"
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
		brief    bool
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
				brief:    false,
			},
			wantErr: false,
		},
		{
			name: "default",
			args: args{
				report:   report,
				filePath: "testdata/tomcat.md",
				brief:    true,
			},
			wantErr: false,
		},
		{
			name: "no os info",
			args: args{
				report:   report,
				filePath: "testdata/no_os_info.md",
				brief:    true,
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
			if err := Export(tt.args.report, tt.args.filePath, tt.args.brief); (err != nil) != tt.wantErr {
				t.Errorf("Export() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
