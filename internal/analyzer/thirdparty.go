package analyzer

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
)

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
