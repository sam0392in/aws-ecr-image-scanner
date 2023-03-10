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

package main

import (
  "os"
  "strings"

  "github.com/alecthomas/kingpin/v2"
  "github.com/sam0392in/aws-ecr-image-scanner/internal/scanner"
)

var (
  app = kingpin.New("aws-ecr-image-scanner", "CLI for seeing the details of vulnerabilities in ECR image.")

  scan          = app.Command("scan", "")
  awsRegion     = scan.Flag("region", "Enter AWS Region").Required().String()
  repo          = scan.Flag("repo", "Enter Repository Name").Required().String()
  imageTag      = scan.Flag("tag", "Enter Image Tag").Required().String()
  inputSeverity = scan.Flag("severity", "comma separated multiple choice, options: critical/high/medium/low/informational/all").Required().String()
)

func main() {
  switch kingpin.MustParse(app.Parse(os.Args[1:])) {
  case scan.FullCommand():
    var data scanner.ScanDetails
    data.ImageTag = *imageTag
    data.Repo = *repo
    data.AwsRegion = *awsRegion
    data.InputSeverity = strings.Split(*inputSeverity, ",")
    data.ScanImage()
  }
}
