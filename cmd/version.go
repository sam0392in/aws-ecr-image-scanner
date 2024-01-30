/*
version.go defines a subcommand named "version" that prints the version number of the application.
*/

package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
)

// The init() function adds the versionCmd to the root command.
func init() {
  rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
  Use:   "version",
  Short: "Print the version number of Holidu ECR Scanner",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("aws-ecr-image-scanner 1.2.0")
  },
}
