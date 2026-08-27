// this is WAF, built using golang
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
	"os"
	"sync"
	"strconv"
	"encoding/csv"
)

var backendProxy *httputil.ReverseProxy //acts as proxy for my waf
var (
    logFile   *os.File
    csvWriter *csv.Writer
    logMutex  sync.Mutex //to lock and unlock the file after goroutines are done accessing and modifying the file
)


type FeatureVector struct {
	URLLength   float64
	PathLength  float64
	QueryLength float64
	NumParams   float64
	NumQuotes   float64
	BodyLength  float64
	NumPercent float64
	NumSemicolons float64
	NumDashes float64
	NumSlashes float64
	NumDots float64
	HasSQLKeywords float64
	HasXSSKeywords float64
	HasPathTraversal float64
	HeaderCount float64 
	MethodGET float64
	MethodPOST float64

}

type MLResponse struct {
	IsAttack   bool    `json:"is_attack"`
	Confidence float64 `json:"confidence"`
}

func extractFeatures(r *http.Request) FeatureVector {
	fullURL := r.URL.String()
	path := r.URL.Path
	query := r.URL.RawQuery

	var bodyLength float64
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		bodyLength = float64(len(bodyBytes))
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes)) //to recover the stream of bytes
	}

	return FeatureVector{
		URLLength:   float64(len(fullURL)),
		PathLength:  float64(len(path)),
		QueryLength: float64(len(query)),
		NumParams:   float64(len(r.URL.Query())),
		NumQuotes:   float64(strings.Count(fullURL, "'")),
		BodyLength:  bodyLength,
	}

}

// sends features extracted to ml through an api in python and get the mlresponse to classify it as an attack or not
func MLapiPy(feature FeatureVector) (MLResponse, error) {
	//convert features to json
	jsonData, err := json.Marshal(feature)
	if err != nil {
		return MLResponse{}, err //if error, return empty response
	}

	client := &http.Client{Timeout: 2 * time.Second}
	//post the request
	resp, err := client.Post("http://localhost:8080/predict", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return MLResponse{IsAttack: false, Confidence: 0}, err
	}
	//runs at the end of program to stop listening
	defer resp.Body.Close()
	//read python response
	var response MLResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	return response, err

}

func wafHandler(w http.ResponseWriter, r *http.Request) {
	features := extractFeatures(r)

	mlres, err := MLapiPy(features)
	if err != nil {
		// FAIL-CLOSED: ML is down,Block with 503
		log.Printf(" WAF ML Service unavailable: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Security verification unavailable at this moment. Please try again later.",
		})
		return
	}

	// Decision: Block or Allow
	if mlres.Confidence > 0.7 && mlres.IsAttack {
		log.Printf("BLOCKED! ATTACK INTERCEPTED!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      " Attack detected and blocked by ML-WAF",
			"confidence": mlres.Confidence,
		})
		return //Stop here, don't forward to backend
	}

	// Forward to backend (Safe)
	log.Printf("ALLOWED (confidence: %.2f)", mlres.Confidence)
	backendProxy.ServeHTTP(w, r)
}

func boolToFloat(b bool) float64 {
    if b {
        return 1.0
    }
    return 0.0
}

//initialises the backend proxy 
func init() {
	backendURL, _ := url.Parse("http://localhost:3000")
	backendProxy = httputil.NewSingleHostReverseProxy(backendURL)
}

//prepping the csv file of logs to be fed to ml model for further analysis


func logRequest(r *http.Request, feature FeatureVector, mlresp MLResponse) {
    record := []string{
        time.Now().Format(time.RFC3339),
        r.RemoteAddr,
        r.Method,
        r.URL.String(),
        strconv.FormatFloat(feature.URLLength, 'f', 2, 64),
        strconv.FormatFloat(feature.PathLength, 'f', 2, 64),
        strconv.FormatFloat(feature.QueryLength, 'f', 2, 64),
        strconv.FormatFloat(feature.NumParams, 'f', 0, 64),
        strconv.FormatFloat(feature.NumQuotes, 'f', 0, 64),
        strconv.FormatFloat(feature.NumPercent, 'f', 0, 64),
        strconv.FormatFloat(feature.NumSemicolons, 'f', 0, 64),
        strconv.FormatFloat(feature.NumDashes, 'f', 0, 64),
        strconv.FormatFloat(feature.NumSlashes, 'f', 0, 64),
        strconv.FormatFloat(feature.NumDots, 'f', 0, 64),
        strconv.FormatFloat(feature.HasSQLKeywords, 'f', 0, 64),
        strconv.FormatFloat(feature.HasXSSKeywords, 'f', 0, 64),
        strconv.FormatFloat(feature.HasPathTraversal, 'f', 0, 64),
        strconv.FormatFloat(feature.BodyLength, 'f', 2, 64),
        strconv.FormatFloat(feature.HeaderCount, 'f', 0, 64),
        strconv.FormatFloat(feature.MethodGET, 'f', 0, 64),
        strconv.FormatFloat(feature.MethodPOST, 'f', 0, 64),
        strconv.FormatFloat(boolToFloat(mlresp.IsAttack), 'f', 0, 64),
        strconv.FormatFloat(mlresp.Confidence, 'f', 4, 64),
    }

    logMutex.Lock()
    defer logMutex.Unlock()

    csvWriter.Write(record)
    csvWriter.Flush()
}


func main() {
	http.HandleFunc("/", wafHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))

}
