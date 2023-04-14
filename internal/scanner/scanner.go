/*
Copyright 2022 Samarth Kanungo.
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

package scanner

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/lensesio/tableprinter"
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
	Name            string      `header:"name"`
	Severity        string      `header:"severity"`
	Description     interface{} `header:"description"`
	Package_name    string      `header:"package_name"`
	Package_version string      `header:"package_version"`
}

type Block struct {
	Try     func()
	Catch   func(Exception)
	Finally func()
}

type Exception interface{}

func throw(up Exception) {
	panic(up)
}

func (tcf Block) Do() {
	if tcf.Finally != nil {
		defer tcf.Finally() // when finally is not nil then go to finally
	}
	if tcf.Catch != nil { // when catch is not nil then pass recover() to catch
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
			out.Package_name = *a.Value
		}
		if *a.Key == "package_version" {
			out.Package_version = *a.Value
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
		out.Package_name = *a.Name
		out.Package_version = *a.Version
	}
	return out
}

/*
sort the output depending upon input severity
*/
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

func tableOutput() *tableprinter.Printer {
	printer := tableprinter.New(os.Stdout)
	printer.BorderTop, printer.BorderBottom, printer.BorderLeft, printer.BorderRight = true, true, true, true
	printer.CenterSeparator = "│"
	printer.ColumnSeparator = "│"
	printer.RowSeparator = "─"
	return printer
}

func printOutput(vulnerabilities [][]scanOutput) {
	printer := tableOutput()
	for _, v := range vulnerabilities {
		printer.Print(&v)
	}
}

/*
start ECR Image Scan
*/
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
		time.Sleep(30 * time.Second)
	} else {
		fmt.Println("Scan Status: ", *scanOut.ImageScanStatus.Status)
	}

}

/*
Returns Paginated output of DescribeImageScanFindingsOutput
*/
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

	/*
	   Waiter: Waits till the image scan is completed
	*/
	fmt.Println("\nSTATUS: waiting to get scan status...")
	opts := request.WithWaiterMaxAttempts(d.MaxRetries)
	//delayer := request.ConstantWaiterDelay(1 * time.Second)
	//opts := request.WithWaiterDelay(delayer)
	//err := client.WaitUntilImageScanComplete(params)
	err := client.WaitUntilImageScanCompleteWithContext(context.TODO(), params, opts)
	if err != nil {
		fmt.Println("INFO: ", err)
	} else {
		fmt.Println("\nSTATUS: ECR Image Scan Completed ..!!!\n")
	}

	/*
	   Start populating scan findings
	*/
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
		fmt.Println("Awesome..!! No vulnerabilities found matching input severity..")
	} else {
		printOutput(vulnerabilities)
	}
	return nil
}
