package cmd

import (
  "fmt"
  "os"
  "regexp"
  "strings"

  "github.com/sam0392in/aws-ecr-image-scanner/internal/scanner"

  "github.com/spf13/cobra"
)

// Define the sub command and call the execution in line 18
var scanCmd = &cobra.Command{
  Use:   "scan",
  Short: "Execute a vulnerability scan and display the results",
  Run: func(cmd *cobra.Command, args []string) {
    run(cmd)
  },
}

//  The init() function sets up the flags for the scan command.
func init() {
  rootCmd.AddCommand(scanCmd)
  scanCmd.Flags().String("repo", "", "Repository name")
  scanCmd.Flags().String("tag", "", "Image tag")
  scanCmd.Flags().String("severity", "high",
    "Comma separated severity levels to scan for, options: critical/high/medium/low/informational/all")
  scanCmd.Flags().Int("max-retry", 5,
    "Define max retry attempt for waiter. Used for increasing delay timeout. 1 retry =~ 5 seconds. "+
      "First retry starts from 2")
  scanCmd.MarkFlagRequired("repo")
  scanCmd.MarkFlagRequired("tag")
}

// run function is the actual logic executed when the "scan" command is run.
func run(cmd *cobra.Command) {
  var data scanner.ScanDetails
  data.ImageTag, _ = cmd.Flags().GetString("tag")
  data.Repo, _ = cmd.Flags().GetString("repo")
  severities, _ := cmd.Flags().GetString("severity")
  data.InputSeverity = strings.Split(severities, ",")
  data.MaxRetries, _ = cmd.Flags().GetInt("max-retry")
  err := data.ScanImage()
  if err != nil {
    scanNotFound, _ := regexp.MatchString("ScanNotFoundException:", err.Error())
    if scanNotFound {
      fmt.Println("Scan not enabled, starting scan now..!!")
      data.StartScan()
      err := data.ScanImage()
      if err != nil {
        fmt.Println("ERROR: ", err)
        os.Exit(1)
      }
    }
    os.Exit(0)
  }
}
