package main

import (
    "bufio"
    "crypto/sha1"
    "flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
    "regexp"
    "strings"
    "syscall"
    "golang.org/x/term"
)

func main() {
    var concealed bool
    var verbose bool
    flag.BoolVar(&concealed, "c", false, "conceal password input")
    flag.BoolVar(&verbose, "v", false, "verbose output (show responses)")
    flag.Parse()
    pwd := ""

    if concealed {
        fmt.Print("Enter password to check (concealed): ")
        bytepwd, err := term.ReadPassword(int(syscall.Stdin))
        if err != nil {
            os.Exit(1)
        }
        fmt.Print("\n")
        pwd = string(bytepwd)
    } else {
        fmt.Print("Enter password to check: ")
        scanner := bufio.NewScanner(os.Stdin)
	    scanner.Scan()
        pwd = scanner.Text()
    }

    // https://gobyexample.com/sha1-hashes
    hash := sha1.New()
    hash.Write([]byte(pwd))
    pwd = ""
    byte_slice := hash.Sum(nil)
    hash_hex := fmt.Sprintf("%x", byte_slice)
    hash_prefix := hash_hex[0:5]

	// perform GET request with first 5 SHA-1 characters
    req_url := "https://api.pwnedpasswords.com/range/" + hash_prefix
    req, err := http.NewRequest("GET", req_url, nil)
    if err != nil {
        panic(err)
    }
    // add padding by default
    // https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding
    req.Header.Set("add-padding", "true")

    resp, err := http.DefaultClient.Do(req)
	if err != nil {
	    fmt.Println(err)
	}

	// read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
	    fmt.Println(err)
	}
	sb := string(body)

    if verbose {
        fmt.Print("\n" + sb + "\n\n")
    }

    hash_suffix:= strings.ToUpper(hash_hex[5:40])

    // checking for substring, therefore not anchoring search at beginning of line
    pattern := regexp.MustCompile(hash_suffix + `:(\d+)`)
    submatch := pattern.FindStringSubmatch(sb)

    if len(submatch) == 2 {  // full match plus group
        fmt.Print("PWNED: " + hash_suffix + ", Occurrences " + submatch[1])
    } else {
        fmt.Print("No matches")
    }
}
