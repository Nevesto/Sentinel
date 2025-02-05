package analyzer

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

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
