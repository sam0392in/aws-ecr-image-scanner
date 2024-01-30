package scanner

import (
  "context"
  "fmt"
  "os"
  "regexp"
  "strings"

  "github.com/aws/aws-sdk-go/aws"
  "github.com/aws/aws-sdk-go/aws/request"
  "github.com/aws/aws-sdk-go/aws/session"
  "github.com/aws/aws-sdk-go/service/ecr"
  "github.com/jedib0t/go-pretty/v6/table"
  "github.com/jedib0t/go-pretty/v6/text"
)

var (
  out scanOutput
)

type ScanDetails struct {
  Repo, ImageTag string
  InputSeverity  []string
  MaxRetries     int
}

type scanOutput struct {
  Name           string      `header:"name"`
  Severity       string      `header:"severity"`
  Description    interface{} `header:"description"`
  PackageName    string      `header:"package_name"`
  PackageVersion string      `header:"package_version"`
}

type Block struct {
  Try     func()
  Catch   func(Exception)
  Finally func()
}

type Exception interface{}

func (tcf Block) Do() {
  if tcf.Finally != nil {
    defer tcf.Finally()
  }
  if tcf.Catch != nil {
    defer func() {
      if r := recover(); r != nil {
        tcf.Catch(r)
      }
    }()
  }
  tcf.Try()
}

func ecrClient() *ecr.ECR {
  awsProfile := os.Getenv("AWS_PROFILE")
  mySession := session.Must(session.NewSessionWithOptions(session.Options{
    SharedConfigState: session.SharedConfigEnable,
    Profile:           awsProfile,
  }))
  svc := ecr.New(mySession, aws.NewConfig())
  return svc
}

func contains(s []string, str string) bool {
  for _, v := range s {
    if str == "all" {
      return true
    }
    if strings.ToUpper(v) == str {
      return true
    }
  }
  return false
}

func sortData(f *ecr.ImageScanFinding) scanOutput {
  Block{
    Try: func() {
      out.Description = *f.Description
    },
    Catch: func(e Exception) {
      out.Description = ""
    },
    Finally: func() {
    },
  }.Do()
  out.Name = *f.Name
  out.Severity = *f.Severity
  for _, a := range f.Attributes {
    if *a.Key == "package_name" {
      out.PackageName = *a.Value
    }
    if *a.Key == "package_version" {
      out.PackageVersion = *a.Value
    }
  }
  return out
}

func sortEnhancedData(f *ecr.EnhancedImageScanFinding) scanOutput {
  Block{
    Try: func() {
      out.Description = *f.Description
    },
    Catch: func(e Exception) {
      out.Description = ""
    },
    Finally: func() {
    },
  }.Do()
  out.Name = *f.PackageVulnerabilityDetails.VulnerabilityId
  out.Severity = *f.Severity
  for _, a := range f.PackageVulnerabilityDetails.VulnerablePackages {
    out.PackageName = *a.Name
    out.PackageVersion = *a.Version
  }
  return out
}

func (d *ScanDetails) getOutput(page *ecr.DescribeImageScanFindingsOutput) []scanOutput {
  var (
    findings []scanOutput
  )

  if len(page.ImageScanFindings.Findings) != 0 {
    for _, f := range page.ImageScanFindings.Findings {
      var data scanOutput
      if d.InputSeverity[0] == "all" {
        data = sortData(f)
      } else if contains(d.InputSeverity, *f.Severity) {
        data = sortData(f)
      } else {
        continue
      }
      findings = append(findings, data)
    }
  } else if (len(page.ImageScanFindings.Findings) == 0) && (len(page.ImageScanFindings.EnhancedFindings) != 0) {
    for _, f := range page.ImageScanFindings.EnhancedFindings {
      var data scanOutput
      if d.InputSeverity[0] == "all" {
        data = sortEnhancedData(f)
      } else if contains(d.InputSeverity, *f.Severity) {
        data = sortEnhancedData(f)
      } else {
        continue
      }
      findings = append(findings, data)
    }
  } else {
    fmt.Println("INFO: No records returned from ECR in current page..!!")
  }

  if len(findings) == 0 {
    return nil
  } else {
    return findings
  }
}

func getRow(scanOutput *scanOutput) table.Row {
  return table.Row{
    scanOutput.Name,
    scanOutput.Severity,
    scanOutput.Description,
    scanOutput.PackageName,
    scanOutput.PackageVersion}
}
func getTableWriter() table.Writer {
  printer := table.NewWriter()
  printer.SetStyle(table.StyleLight)
  printer.SetOutputMirror(os.Stdout)
  printer.AppendHeader(table.Row{"NAME", "SEVERITY", "DESCRIPTION", "PACKAGE", "VERSION"})
  printer.SetColumnConfigs([]table.ColumnConfig{
    {
      Name:             "DESCRIPTION",
      WidthMax:         56,
      WidthMaxEnforcer: text.WrapSoft,
    },
  })

  return printer
}

func printOutput(vulnerabilities [][]scanOutput) {
  printer := getTableWriter()
  for _, v := range vulnerabilities {
    for _, vul := range v {
      printer.AppendRow(getRow(&vul))
    }
  }
  printer.Render()
}

func (d *ScanDetails) StartScan() {
  imageId := &ecr.ImageIdentifier{
    ImageTag: &d.ImageTag,
  }
  scanParams := &ecr.StartImageScanInput{
    ImageId:        imageId,
    RepositoryName: &d.Repo,
  }
  client := ecrClient()
  scanOut, err := client.StartImageScan(scanParams)
  if err != nil {

    fmt.Println(err)
  }
  status := *scanOut.ImageScanStatus.Status
  scanInProgress, _ := regexp.MatchString("IN_PROGRESS", status)
  if scanInProgress {
    fmt.Println("Image scanning in progress...!!")
  } else {
    fmt.Println("Scan Status: ", *scanOut.ImageScanStatus.Status)
  }

}

func (d *ScanDetails) ScanImage() error {
  var vulnerabilities [][]scanOutput
  client := ecrClient()
  imageId := &ecr.ImageIdentifier{
    ImageTag: &d.ImageTag,
  }

  params := &ecr.DescribeImageScanFindingsInput{
    ImageId:        imageId,
    RepositoryName: &d.Repo,
  }

  fmt.Println("\nSTATUS: Waiting to get scan status...")
  opts := request.WithWaiterMaxAttempts(d.MaxRetries)
  err := client.WaitUntilImageScanCompleteWithContext(context.TODO(), params, opts)
  fmt.Println("\nSTATUS: ECR Image Scan Completed ..!!!")

  pageNum := 0
  err = client.DescribeImageScanFindingsPages(params,
    func(page *ecr.DescribeImageScanFindingsOutput, lastPage bool) bool {
      pageNum++
      vulnerability := d.getOutput(page)
      if vulnerability != nil {
        vulnerabilities = append(vulnerabilities, vulnerability)
      }
      return pageNum <= pageNum
    })
  if err != nil {
    return err
  }

  if len(vulnerabilities) == 0 {
    fmt.Println("STATUS: NO_VULNERABILITIES_FOUND")
  } else {
    fmt.Println("STATUS: VULNERABILITIES_FOUND")
    printOutput(vulnerabilities)
    return fmt.Errorf("VulnerabilitiesFoundException")
  }
  return nil
}
