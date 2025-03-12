package excel

import (
	"github.com/aquasecurity/trivy/pkg/types"
	utils "github.com/miao2sec/trivy-plugin-report/utils"
	"strings"
	"testing"
)

func TestExport(t *testing.T) {
	type args struct {
		report   *types.Report
		filePath string
		beautify bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "default",
			args: args{
				report: nil,
				// 请保持 json 文件和 xlsx 文件同名
				filePath: "testdata/vpt_java_test.xlsx",
				beautify: false,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := utils.ReadJSONFromFile(strings.Replace(tt.args.filePath, ".xlsx", ".json", -1))
			if err != nil {
				panic(err)
			}
			if err := Export(report, tt.args.filePath, tt.args.beautify); (err != nil) != tt.wantErr {
				t.Errorf("Export() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
