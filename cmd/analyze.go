package cmd

import (
	"fmt"

	"sentinel/internal/analyzer"

	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [URL]",
	Short: "Analyze a website and return privacy & security information",
	Long:  `The analyze command examines a specific website and provides information such as technologies used, collected data, data sharing, and associated risks.`,
	Args:  cobra.ExactArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		fmt.Println("Analyzing the site", url)

		analyzer.DetectTechnologies(url)
		analyzer.CheckCookies(url)
		analyzer.CheckThirdPartyDomains(url)
		analyzer.CheckSecurity(url)
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}
