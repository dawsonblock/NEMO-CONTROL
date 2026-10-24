// abi-verdict streams invocation-ABI verdicts for the cross-language
// differential harness (scripts/abi-differential.mjs).
//
// Protocol: each stdin line carries one base64-encoded wire request; each
// stdout line reports the Go parser's verdict for that input, in order —
// "accept", or "reject<TAB><message>". Every input line produces exactly
// one output line, including an empty line (an empty wire is a reject).
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/openclaw/crabbox/internal/execution"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	for scanner.Scan() {
		wire, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			fmt.Fprintf(os.Stderr, "abi-verdict: input line is not base64: %v\n", err)
			os.Exit(2)
		}
		if _, err := execution.ParseInvocationRequest(wire); err != nil {
			fmt.Fprintf(out, "reject\t%s\n", err)
		} else {
			fmt.Fprintln(out, "accept")
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "abi-verdict: read stdin: %v\n", err)
		os.Exit(2)
	}
	if err := out.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "abi-verdict: write stdout: %v\n", err)
		os.Exit(2)
	}
}
