package cmd

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/spf13/cobra"
)

func ensureProtocol(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	return urlStr
}

func DetectTechnologies(urlStr string) {
	urlStr = ensureProtocol(urlStr)

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		log.Printf("Error parsing URL: %v", err)
		return
	}

	if parsedURL.Host == "" {
		log.Printf("Error: URL without a valid domain.")
		return
	}

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Printf("Error creating Wappalyzer client: %v", err)
		return
	}

	response, err := http.Get(parsedURL.String())
	if err != nil {
		log.Printf("Error accessing site %s: %v", parsedURL.String(), err)
		return
	}
	defer response.Body.Close()

	headers := response.Header

	var body []byte
	if response.ContentLength != -1 {
		body = make([]byte, response.ContentLength)
		_, err = response.Body.Read(body)
	} else {
		body, err = io.ReadAll(response.Body)
	}
	if err != nil {
		log.Printf("Error reading response body from %s: %v", parsedURL.String(), err)
		return
	}

	technologies := wappalyzerClient.Fingerprint(headers, body)

	fmt.Println("Detected technologies:")
	for tech := range technologies {
		fmt.Println("  -", tech)
	}
}

func CheckCookies(urlStr string) {
	urlStr = ensureProtocol(urlStr)

	resp, err := http.Get(urlStr)
	if err != nil {
		fmt.Printf("Error accessing %s: %v\n", urlStr, err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Collected cookies:")
	for _, cookie := range resp.Cookies() {
		fmt.Printf("  - %s: %s\n", cookie.Name, cookie.Value)
	}
}

func CheckThirdPartyDomains(urlStr string) {
	urlStr = ensureProtocol(urlStr)

	resp, err := http.Get(urlStr)
	if err != nil {
		log.Printf("Error accessing %s: %v\n", urlStr, err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Third-party domains detected:")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body from %s: %v", urlStr, err)
		return
	}

	domainSet := make(map[string]struct{})
	parsedURL, _ := url.Parse(urlStr)

	re := regexp.MustCompile(`https?:\/\/[a-zA-Z0-9.\-]+`)
	matches := re.FindAllString(string(body), -1)

	for _, match := range matches {
		thirdPartyURL, _ := url.Parse(match)
		if thirdPartyURL.Host != "" && thirdPartyURL.Host != parsedURL.Host {
			domainSet[thirdPartyURL.Host] = struct{}{}
		}
	}

	if len(domainSet) == 0 {
		fmt.Println("  - No third-party domains found.")
		return
	}

	for domain := range domainSet {
		fmt.Println("  -", domain)
	}
}

func CheckSecurity(urlStr string) {
	urlStr = ensureProtocol(urlStr)

	resp, err := http.Get(urlStr)
	if err != nil {
		fmt.Printf("Error accessing %s: %v\n", urlStr, err)
		return
	}
	defer resp.Body.Close()

	if resp.Request.URL.Scheme != "https" {
		fmt.Println("Warning: The site does not use secure HTTPS!")
	} else {
		fmt.Println("The site uses secure HTTPS.")
	}

	fmt.Println("Security headers:")
	fmt.Printf("  - X-Content-Type-Options: %s\n", resp.Header.Get("X-Content-Type-Options"))
	fmt.Printf("  - Content-Security-Policy: %s\n", resp.Header.Get("Content-Security-Policy"))
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [URL]",
	Short: "Analyze a website and return relevant information",
	Long:  `The analyze command examines a specific website and provides information such as technologies used, collected data, data sharing, and associated risks.`,
	Args:  cobra.ExactArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		fmt.Println("Analyzing the site", url)

		DetectTechnologies(url)
		CheckCookies(url)
		CheckThirdPartyDomains(url)
		CheckSecurity(url)
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}
