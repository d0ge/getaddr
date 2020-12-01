package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

const banner = `
getaddr v0.1
`

// MaxRecursionDepth is limit of recursion to protect of OOM
const MaxRecursionDepth = 8388608

// Version is the current version of httpx
const Version = `0.1`

// this is a comment
// pay attention that behavior netdns=go/cgo may diff
// export GODEBUG=netdns=go    # force pure Go resolver
// export GODEBUG=netdns=cgo   # force cgo resolver
// we are interesting at cgo resolver
// Build tags: go build -tags netcgo getaddr.go

func main() {
	options := parseOptions()
	resolver(options)
}

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Printf("%s\n", banner)
}
func parseOptions() *Options {
	options := &Options{}
	flag.IntVar(&options.Threads, "threads", 50, "Number of threads")
	flag.IntVar(&options.Skip, "skip", 0, "Number of combinations to skip")
	flag.IntVar(&options.Depth, "depth", 2, "Max number of chars at fuzz string")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&options.Version, "version", false, "Show version of ufuzz")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose Mode")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.StringVar(&options.InputSpecialCharsets, "charset", "0,1,2", "Special charsets to fuzz")
	flag.StringVar(&options.InputDomainNames, "domains", "127.0.0.1,127.0.0.2", "Domain names comma separated")
	flag.BoolVar(&options.StoreResponse, "so", false, "Save output to directory (default 'corpus')")
	flag.StringVar(&options.StoreResponseDirectory, "sod", "corpus", "Directory to write output in go-fuzz format (optional)")

	flag.Parse()

	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Infof("Current Version: %s\n", Version)
		os.Exit(0)
	}

	options.validateOptions()

	return options
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.MaxLevel = gologger.Verbose
	}
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}

func (options *Options) validateOptions() {
	options.domainNames = SplitByCharAndTrimSpace(options.InputDomainNames, ",")
	var pow int = options.Depth*options.Depth*options.Depth - 1
	if options.Skip > pow {
		gologger.Fatalf("Invalid value for skip, %d is bigger then %d^3 - 1", options.Skip, options.Depth)
	}

	var err error
	if len(options.domainNames) != 2 {
		gologger.Fatalf("Invalid value for domains, only two domains supported")
	} else {
		gologger.Printf("Used domains")
		for _, domain := range options.domainNames {
			ips, _ := net.LookupIP(domain)
			if ips != nil {
				gologger.Printf("%s %s", domain, ips)
			} else {
				gologger.Printf("%s [not resolved]", domain)
			}
		}
	}
	if options.specialCharsets, err = StringToSliceInt(options.InputSpecialCharsets); err != nil {
		gologger.Fatalf("Invalid value for special chars option: %s\n", err)
	}
	options.specialBytes = sliceintToByteSlice(options.specialCharsets)

	// Try to create output folder if it doesnt exist
	if options.StoreResponse && !folderExists(options.StoreResponseDirectory) {
		if err := os.MkdirAll(options.StoreResponseDirectory, os.ModePerm); err != nil {
			gologger.Fatalf("Could not create output directory '%s': %s\n", options.StoreResponseDirectory, err)
		}
	}
}

// FolderExists checks if a folder exists
func folderExists(folderpath string) bool {
	_, err := os.Stat(folderpath)
	return !os.IsNotExist(err)
}

func sliceintToByteSlice(input []int) []byte {
	var specials0 = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	var specials1 = []byte{32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47}
	var specials2 = []byte{58, 59, 60, 61, 62, 63, 64}
	var specials3 = []byte{91, 92, 93, 94, 95, 96}
	var specials4 = []byte{123, 124, 125, 126}
	var specials5 = []byte{48, 49, 88, 120} // 0 1 X x
	specials := make([][]byte, 6)
	specials[0] = specials0
	specials[1] = specials1
	specials[2] = specials2
	specials[3] = specials3
	specials[4] = specials4
	specials[5] = specials5
	prod := make([]byte, 0)
	for _, v := range input {
		if v > 5 {
			gologger.Fatalf("Invalid value for special chars option: value should be 0,1,2,3,4,5 only, got %d", v)
		} else {
			for _, i := range specials[v] {
				prod = append(prod, i)
			}
		}
	}
	var str string = ""
	for _, b := range prod {
		var space = byte(' ')
		if b < space {
			str += fmt.Sprintf("0x%02d ", b)
		} else {
			str += fmt.Sprintf("%s ", string(b))
		}
	}
	gologger.Printf("Used charsets: [%s]", str)
	return prod
}

func resolver(options *Options) {
	var input string = ""
	for i := 0; i < options.Depth; i++ {
		input = input + fmt.Sprintf("%d", i)
	}
	prod := product(input, 3)
	for i := options.Skip; i < len(prod); i++ {
		var item = prod[i]
		if item[1] == '0' {
			continue
		}
		gologger.Infof("%d) Combination %s\n", i, item)
		fuzz(options, item)
	}
}

// StringToSliceInt converts string to slice of ints
func StringToSliceInt(s string) ([]int, error) {
	var r []int
	if s == "" {
		return r, nil
	}
	for _, v := range strings.Split(s, ",") {
		vTrim := strings.TrimSpace(v)
		if i, err := strconv.Atoi(vTrim); err == nil {
			r = append(r, i)
		} else {
			return r, err
		}
	}

	return r, nil
}

// SplitByCharAndTrimSpace splits string by a character and remove spaces
func SplitByCharAndTrimSpace(s, splitchar string) (result []string) {
	for _, token := range strings.Split(s, splitchar) {
		result = append(result, strings.TrimSpace(token))
	}
	return
}
func iface(input string) []interface{} {
	var list = strings.Split(input, "")
	vals := make([]interface{}, len(list))
	for i, v := range list {
		vals[i] = v
	}
	return vals
}
func chunkBy(items []string, chunkSize int) (chunks [][]string) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}

	return append(chunks, items)
}

func fuzz(options *Options, combination string) {
	var c string = "%s"
	var slice []int
	var sum int = 0
	for _, digit := range combination {
		var i = int(digit) - int('0')
		slice = append(slice, i)
		sum += i
	}
	var producer = fmt.Sprintf("%s%s%s%s%s", strings.Repeat(c, slice[0]), options.domainNames[0], strings.Repeat(c, slice[1]), options.domainNames[1], strings.Repeat(c, slice[2]))
	var charsets = product(string(options.specialBytes), sum)
	gologger.Infof("Charset %d\n", len(charsets))
	var items = make([]string, 0)
	for _, item := range charsets {
		var params = iface(item)
		var str = fmt.Sprintf(producer, params...)
		items = append(items, str)
	}
	var results = runner(options, chunkBy(items, options.Threads))
	save(options, results)
	write(options, combination, results)
}

func look(wg *sync.WaitGroup, names []string, nums chan []Result) {
	defer wg.Done()
	var results = make([]Result, 0)
	for _, name := range names {
		ips, _ := net.LookupIP(name)
		if ips != nil {
			r := Result{name: name, IPs: ips}
			results = append(results, r)
		}
	}
	nums <- results
}

func runner(options *Options, items [][]string) []Result {
	var threads int = len(items)

	var results []Result
	var wg sync.WaitGroup
	nums := make(chan []Result) // Declare a unbuffered channel
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go look(&wg, items[i], nums)
		var chunk = <-nums // Read the value from unbuffered channel
		for _, item := range chunk {
			results = append(results, item)
		}
	}
	wg.Wait()
	close(nums) // Closes the channel
	return results
}

func save(options *Options, output []Result) {
	var f *os.File
	if options.Output != "" {
		var err error
		f, err = os.OpenFile(options.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			gologger.Fatalf("Could not create output file '%s': %s\n", options.Output, err)
		}
		defer f.Close()
	}
	for _, r := range output {

		var row string = fmt.Sprintf("%q\t%s", r.name, r.IPs)

		gologger.Silentf("%s\n", row)
		if f != nil {
			//nolint:errcheck // this method needs a small refactor to reduce complexity
			f.WriteString(row + "\n")
		}
	}

}

func write(options *Options, combination string, output []Result) {
	if options.StoreResponse {
		for i, item := range output {
			var combinationFile = fmt.Sprintf("%s%d", combination, i)
			responsePath := path.Join(options.StoreResponseDirectory, combinationFile)
			err := ioutil.WriteFile(responsePath, []byte(item.name), 0644)
			if err != nil {
				gologger.Warningf("Could not write response, at path '%s', to disc.", responsePath)
			}
		}
	}
}

func product(input string, n int) []string {
	if n == 0 {
		return nil
	}
	prod := make([]string, 0)
	var counter int = 0
	findAllCombination("", input, n, &prod, &counter)
	return prod
}

func findAllCombination(tmp string, raw string, n int, all *[]string, counter *int) {
	*counter++
	if len(tmp) == n {
		*all = append(*all, tmp)
	} else {
		if *counter < MaxRecursionDepth {
			for i := 0; i < len(raw); i++ {
				findAllCombination(tmp+string(raw[i]), raw, n, all, counter)
			}
		}
	}
}

// Result of a fuzzer
type Result struct {
	name string
	IPs  []net.IP
}

// Options contains configuration options for tiny url fuzzer.
type Options struct {
	Skip                   int
	Threads                int
	Depth                  int
	Silent                 bool
	Version                bool
	Verbose                bool
	StoreResponse          bool
	specialBytes           []byte
	specialCharsets        []int
	domainNames            []string
	Output                 string
	InputSpecialCharsets   string
	InputDomainNames       string
	StoreResponseDirectory string
}
