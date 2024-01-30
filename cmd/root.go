/*
defines the root command using Cobra.
The root command is named "aws-ecr-iamge-scanner," and it has a short description.
*/

package cmd

import (
  "os"

  "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
  Use:   "aws-ecr-image-scanner",
  Short: "CLI for running vulnerability scans on images in ECR and viewing the results.",
}

// Execute The Execute() function is responsible for executing the root command, and it exits with an error code if there's an error during execution.
func Execute() {
  err := rootCmd.Execute()
  if err != nil {
    os.Exit(1)
  }
}
