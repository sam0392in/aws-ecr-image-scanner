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
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/lensesio/tableprinter"
)

var (
	out scanOutput
)

type ScanDetails struct {
	AwsRegion, Repo, ImageTag string
	InputSeverity             []string
}

type scanOutput struct {
	Name            string `header:"name"`
	Severity        string `header:"severity"`
	Description     string `header:"description"`
	Package_name    string `header:"package_name"`
	Package_version string `header:"package_version"`
}

func ecrClient(awsRegion string) *ecr.ECR {
	mySession := session.Must(session.NewSession())
	svc := ecr.New(mySession, aws.NewConfig().WithRegion(awsRegion))
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
	out.Name = *f.Name
	out.Severity = *f.Severity
	out.Description = *f.Description
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

/*
sort the output depending upon input severity
*/
func (d *ScanDetails) getOutput(page *ecr.DescribeImageScanFindingsOutput) []scanOutput {
	var (
		findings []scanOutput
	)
	scanFindings := page.ImageScanFindings.Findings

	for _, f := range scanFindings {
		if d.InputSeverity[0] == "all" {
			out = sortData(f)
		} else {
			if contains(d.InputSeverity, *f.Severity) {
				out = sortData(f)
			}
		}
		if out.Name != "" {
			findings = append(findings, out)
		}
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
Returns Paginated output of DescribeImageScanFindingsOutput
*/
func (d *ScanDetails) ScanImage() {
	var vulnerabilities [][]scanOutput
	client := ecrClient(d.AwsRegion)
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
	err := client.WaitUntilImageScanComplete(params)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("\nECR Image Scan Completed ..!!!\n")
	}

	/*
	   Waiter: Start populating scan findings
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
		fmt.Println(err)
	}

	if len(vulnerabilities) == 0 {
		fmt.Println("Awesome..!! No vulnerabilities found matching input severity..")
	} else {
		printOutput(vulnerabilities)
	}
}
