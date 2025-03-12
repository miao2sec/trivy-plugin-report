package excel

import (
	"fmt"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/miao2sec/trivy-plugin-report/utils"
	"github.com/xuri/excelize/v2"
	"golang.org/x/xerrors"
)

const (
	VulnReport = "漏洞扫描结果"
)

var (
	ResultClass = map[types.ResultClass]string{
		types.ClassOSPkg:   "系统层",
		types.ClassLangPkg: "应用层",
	}
	ResultType = map[ftypes.TargetType]string{
		ftypes.GoBinary: "Go Binary",
	}

	SeverityColor = map[string]string{
		"超危": "FF7675",
		"高危": "FAB1A0",
		"中危": "FFEAA7",
		"低危": "74B9FF",
		"未知": "DFE6E9",
	}

	VulnHeaderValues = []string{
		"扫描对象", "扫描类型", "软件包类别", "漏洞编号", "漏洞名称",
		"威胁等级来源", "威胁等级", "软件包名称", "软件包版本", "软件包路径",
		"修复版本", "漏洞状态", "公布时间", "上次修改时间",
	}
	VulnHeaderWidths = map[string]float64{
		"A": 10, "B": 10, "C": 25, "D": 21, "E": 50,
		"F": 12, "G": 10, "H": 12, "I": 20, "J": 50,
		"K": 20, "L": 42, "M": 25, "N": 25,
	}
	DefaultStyle = excelize.Style{
		Alignment: &excelize.Alignment{WrapText: true, Vertical: "top"},
		Border: []excelize.Border{
			{Type: "left", Style: 1, Color: "000000"},
			{Type: "top", Style: 1, Color: "000000"},
			{Type: "right", Style: 1, Color: "000000"},
			{Type: "bottom", Style: 1, Color: "000000"},
		},
	}
)

// Export export excel file
func Export(report *types.Report, fileName string, beautify bool) (err error) {
	var data []string
	var (
		f       = excelize.NewFile()
		hasVuln = false
		rowNum  = 2 // 记录当前工作表的最后一行
	)

	for _, result := range report.Results {
		if result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg {
			hasVuln = true
			if err = createVulnSheet(f); err != nil {
				return err
			}
			if err = createVulnHeaders(f); err != nil {
				return err
			}

			// add vulnerability
			for _, vuln := range result.Vulnerabilities {
				data, err = parseVulnData(result.Target, result.Type, result.Class, vuln)
				if err != nil {
					return xerrors.Errorf("failed to parse vuln data:%w", err)
				}
				err = f.SetSheetRow(VulnReport, fmt.Sprintf("A%v", rowNum), &data)
				if err != nil {
					return xerrors.Errorf("failed to add vuln %s for sheet %s:%w", vuln.VulnerabilityID,
						VulnReport, err)
				}
				rowNum++
			}

			if err = setVulnSheetStyle(f, beautify); err != nil {
				return err
			}
		}
	}

	// delete default sheet and save excel file
	if err = f.DeleteSheet("Sheet1"); err != nil {
		return xerrors.Errorf("failed to delete default sheet:%w", err)
	}
	if hasVuln {
		if err = f.SaveAs(fileName); err != nil {
			return err
		}
	}

	defer func() {
		if err = f.Close(); err != nil {
			log.Fatal("failed to close excelize file:%w", err)
		}
	}()

	return nil
}

// createVulnSheet creat sheet if sheet of vulnerability is not exist
func createVulnSheet(file *excelize.File) error {
	sheetIndex, err := file.GetSheetIndex(VulnReport)
	if err != nil {
		return xerrors.Errorf("failed to judge if sheet %s is exist:%w", VulnReport, err)
	}
	if sheetIndex == -1 {
		_, err = file.NewSheet(VulnReport)
		if err != nil {
			return xerrors.Errorf("failed to create sheet %s:%w", VulnReport, err)
		}
	}
	return nil
}

// createVulnHeaders create header for vulnerability sheet if not exist, and set column width
func createVulnHeaders(file *excelize.File) error {
	rows, err := file.GetRows(VulnReport)
	if err != nil {
		return xerrors.Errorf("failed to judge if sheet %s has column header:%w", VulnReport, err)
	}
	if len(rows) <= 0 {
		err = file.SetSheetRow(VulnReport, "A1", &VulnHeaderValues)
		if err != nil {
			return xerrors.Errorf("failed to add header for sheet %s:%w", VulnReport, err)
		}
		for col, width := range VulnHeaderWidths {
			if err = file.SetColWidth(VulnReport, col, col, width); err != nil {
				return xerrors.Errorf("failed to set the width of column %s for %s:%w", col, VulnReport, err)
			}
		}
	}
	return nil
}

// setVulnSheetStyle set style for vulnerability sheet
func setVulnSheetStyle(file *excelize.File, beautify bool) error {
	var (
		severityStyle = DefaultStyle
		fill          = excelize.Fill{Type: "pattern", Pattern: 1}
	)
	var (
		defaultStyleId  int
		severityStyleId int
	)

	// get all rows
	rows, err := file.GetRows(VulnReport)
	if err != nil {
		return xerrors.Errorf("failed to get rows data:%w", err)
	}

	for index, row := range rows {
		if index == 0 {
			continue
		}
		if SeverityColor[row[6]] == "" {
			// set default style of cell
			defaultStyleId, err = file.NewStyle(&DefaultStyle)
			if err != nil {
				return xerrors.Errorf("failed to new default style:%w", err)
			}
			err = file.SetCellStyle(VulnReport, cellName(index, 0), cellName(index, len(VulnHeaderValues)-1),
				defaultStyleId)
			if err != nil {
				return xerrors.Errorf("failed to set default style:%w", err)
			}
		}
		if beautify {
			// fill the background color of the cell according to the severity of the vulnerability.
			fill.Color = []string{SeverityColor[row[6]]}
			severityStyle.Fill = fill
			severityStyleId, err = file.NewStyle(&severityStyle)
			if err != nil {
				return xerrors.Errorf("failed to new severity style:%w", err)
			}
			err = file.SetCellStyle(VulnReport, cellName(index, 0), cellName(index, len(VulnHeaderValues)-1),
				severityStyleId)
			if err != nil {
				return xerrors.Errorf("failed to set severity style:%w", err)
			}
		}
	}
	return nil
}

// parseVulnData parse vulnerability data and return a slice of
// Target, Type, Class, Vulnerability ID, Title, Severity Source, Severity, Package Name, Package Version, Package Path,
// Fixed Version, Status, Published Date, and Last Modified Date
func parseVulnData(resultTarget string, resultType ftypes.TargetType, resultClass types.ResultClass,
	vuln types.DetectedVulnerability) ([]string, error) {
	var data []string

	data = append(data, resultTarget)

	if ResultType[resultType] != "" {
		data = append(data, ResultType[resultType])
	} else {
		data = append(data, string(resultType))
	}

	if ResultClass[resultClass] != "" {
		data = append(data, ResultClass[resultClass])
	} else {
		data = append(data, string(resultClass))
	}

	data = append(data, vuln.VulnerabilityID)
	data = append(data, vuln.Title)
	data = append(data, string(vuln.SeveritySource))
	data = append(data, utils.ChineseSeverity[vuln.Severity])
	data = append(data, vuln.PkgName)
	data = append(data, vuln.InstalledVersion)
	data = append(data, vuln.PkgPath)
	data = append(data, vuln.FixedVersion)

	if dbTypes.Statuses[vuln.Status] != "" {
		data = append(data, utils.VulnStatuses[dbTypes.Statuses[vuln.Status]])
	} else {
		data = append(data, dbTypes.Statuses[vuln.Status])
	}

	data = append(data, utils.FormatTime(vuln.PublishedDate, true))
	return append(data, utils.FormatTime(vuln.LastModifiedDate, true)), nil
}

// cellName Construct the cell name according to the row number and column number.
func cellName(rowIndex, colIndex int) string {
	return fmt.Sprintf("%c%v", rune('A'+colIndex), rowIndex+1)
}
