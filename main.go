package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
)

// Create HTTP transports to share pool of connections
var tr = http.DefaultTransport.(*http.Transport).Clone()
var client = &http.Client{Transport: tr}

// GenerateRandomUUID generates a random UUID
func GenerateRandomUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// KeyExists is responsible for checking if key exists and is not nil
func KeyExists(decoded map[string]interface{}, key string) bool {
	val, ok := decoded[key]
	return ok && val != nil
}

// mergeAllKeys makes a new map and merges all ip info together
// specifically for the DNS Leak Test's API, it also fixes some
// bugs with the API
func mergeAllKeys(m []interface{}) map[string]interface{} {
	j := make(map[string]interface{})
	for _, a := range m {
		ip := a.(map[string]interface{})["ip_address"].(string)
		if ip != "" {
			for k, v := range a.(map[string]interface{}) {
				if _, ok := j[ip].(map[string]interface{}); !ok {
					j[ip] = make(map[string]interface{})
				}

				if k == "isp" {
					if ret :=
						acceptableValue("Unknown isp", v.(string)); ret != "" ||
						!KeyExists(j[ip].(map[string]interface{}), k) {
						j[ip].(map[string]interface{})[k] = ret
					}
				} else if k == "city" {
					if ret :=
						acceptableValue("Unknown city", v.(string)); ret != "" ||
						!KeyExists(j[ip].(map[string]interface{}), k) {
						j[ip].(map[string]interface{})[k] = ret
					}
				} else if k == "country" {
					if ret := acceptableValue("Unknown country", v.(string)); ret != "" ||
						!KeyExists(j[ip].(map[string]interface{}), k) {
						j[ip].(map[string]interface{})[k] = ret
					}
				} else if k == "hostname" {
					if v.(string) == "None" || !KeyExists(j[ip].(map[string]interface{}), k) {
						j[ip].(map[string]interface{})[k] = "No PTR"
					}
				} else {
					j[ip].(map[string]interface{})[k] = v
				}
			}
		}
	}
	return j
}

// GetNumberOfDigits returns the number of digits in an integer
func GetNumberOfDigits(number int) (count int) {
	for number != 0 {
		number /= 10
		count += 1
	}
	return
}

// acceptableValue checks if the string is acceptable from the API
func acceptableValue(unacceptable string, valueToCheck string) string {
	if valueToCheck != "" && valueToCheck != unacceptable {
		return valueToCheck
	}
	return "" // empty = not acceptable
}

// doTest resolves DNS for the test and notifies of completion via status
func doTest(uuid string, status chan bool) {
	_, _ = net.LookupIP(uuid + ".test.dnsleaktest.com")
	status <- true
}

// liveStatus shows the how many tests were done
func liveStatus(left int, total int) {
	fmt.Printf("\rTesting %0"+strconv.Itoa(GetNumberOfDigits(total))+"d/%d", left, total)
}

func main() {
	numRuns := flag.Int("num-runs", 36, "number of times to run the test (standard = 6; extended = 36)")
	jsonOutput := flag.Bool("json-output", false, "return json output")
	flag.Parse()

	// Make request UUIDs
	identifiers := make([]interface{}, 0)
	for i := 0; i < *numRuns; i++ {
		identifiers = append([]interface{}{GenerateRandomUUID()}, identifiers...)
	}

	// Register UUIDs for DNS Leak Test to monitor
	j := make(map[string]interface{})
	j["identifiers"] = identifiers
	request, _ := json.Marshal(&j)

	req, _ := http.NewRequest("POST", "https://www.dnsleaktest.com/api/v1/identifiers", bytes.NewBuffer(request))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "https://github.com/rany2")

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	// Do tests in goroutines
	status := make(chan bool, 1)
	for _, v := range identifiers {
		go doTest(v.(string), status)
	}

	// Wait for all goroutines to be done and send status
	liveStatus(0, len(identifiers))
	for i := 0; i < len(identifiers); i++ {
		<-status
		liveStatus(i+1, len(identifiers))
	}
	fmt.Println()

	// Get results of the test
	j = make(map[string]interface{})
	j["queries"] = identifiers
	request, _ = json.Marshal(&j)
	req, _ = http.NewRequest("POST", "https://www.dnsleaktest.com/api/v1/servers-for-result", bytes.NewBuffer(request))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "https://github.com/rany2")

	resp, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if *jsonOutput {
		fmt.Print(string(body))
	} else {
		var j []interface{}
		err = json.Unmarshal(body, &j)
		if err != nil {
			panic(err)
		}
		jNew := mergeAllKeys(j)

		fmt.Println()
		fmt.Println("Test complete:")
		k := 0
		for _, v := range jNew {
			if !KeyExists(v.(map[string]interface{}), "ip_address") && !KeyExists(v.(map[string]interface{}), "hostname") {
				continue
			}
			k += 1

			str := "  " +
				strconv.Itoa(k) +
				") " +
				v.(map[string]interface{})["ip_address"].(string) +
				" (" +
				v.(map[string]interface{})["hostname"].(string) +
				")"

			if KeyExists(v.(map[string]interface{}), "isp") {
				displayISP := acceptableValue("Unknown isp", v.(map[string]interface{})["isp"].(string))
				str += " hosted by " + displayISP
			}

			var displayCity, displayCountry string
			if KeyExists(v.(map[string]interface{}), "city") {
				displayCity = acceptableValue("Unknown city", v.(map[string]interface{})["city"].(string))
			}

			if KeyExists(v.(map[string]interface{}), "country") {
				displayCountry = acceptableValue("Unknown country", v.(map[string]interface{})["country"].(string))
			}

			if displayCity != "" || displayCountry != "" {
				str += " in"
			}

			if displayCity != "" {
				str += " " + displayCity
				if displayCountry != "" {
					str += ","
				}
			}

			if displayCountry != "" {
				str += " " + displayCountry
			}

			fmt.Println(str)
		}
	}
}
