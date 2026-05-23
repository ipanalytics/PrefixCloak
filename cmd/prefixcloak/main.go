package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"prefixcloak/internal/cloak"
	"prefixcloak/internal/policy"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "prefixcloak:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("prefixcloak", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		policyFile  = fs.String("policy", "", "YAML policy file")
		inFile      = fs.String("in", "", "input file; defaults to stdin")
		outFile     = fs.String("out", "", "output file; defaults to stdout")
		mode        = fs.String("mode", "", "override mode: pseudonymous or anonymous")
		keyHex      = fs.String("key-hex", "", "PrefixCloak key as hex")
		keyBase64   = fs.String("key-base64", "", "PrefixCloak key as base64")
		keyFile     = fs.String("key-file", "", "file containing key as hex, base64, hex:<value>, or base64:<value>")
		genKey      = fs.Bool("generate-key", false, "generate a new PrefixCloak key and print it")
		printReport = fs.Bool("report", true, "print a GDPR-aware processing report to stderr")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *genKey {
		key, err := cloak.GenerateKey()
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "hex:%s\nbase64:%s\n", hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key))
		return nil
	}

	p, err := policy.Load(*policyFile)
	if err != nil {
		return err
	}
	if *mode != "" {
		p.Mode = cloak.Mode(*mode)
	}

	key, err := cloak.LoadKey(*keyHex, *keyBase64, *keyFile)
	if err != nil {
		return err
	}
	c, err := cloak.New(key, p.CloakConfig())
	if err != nil {
		return err
	}

	input := stdin
	if *inFile != "" {
		f, err := os.Open(*inFile)
		if err != nil {
			return err
		}
		defer f.Close()
		input = f
	}

	output := stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			return err
		}
		defer f.Close()
		output = f
	}

	stats, err := transformStream(c, input, output)
	if err != nil {
		return err
	}
	if *printReport {
		writeReport(stderr, p, stats)
	}
	return nil
}

type stats struct {
	Lines int
}

func transformStream(c *cloak.Cloaker, input io.Reader, output io.Writer) (stats, error) {
	var s stats
	scanner := bufio.NewScanner(input)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 8*1024*1024)
	for scanner.Scan() {
		line, err := c.TransformLine(scanner.Text())
		if err != nil {
			return s, err
		}
		if _, err := fmt.Fprintln(output, line); err != nil {
			return s, err
		}
		s.Lines++
	}
	return s, scanner.Err()
}

func writeReport(w io.Writer, p policy.Policy, s stats) {
	label := "pseudonymized personal data"
	if p.Mode == cloak.ModeAnonymous {
		label = "anonymous output, if the key is not retained and truncation is sufficient for the dataset"
	}
	fmt.Fprintln(w, "PrefixCloak report")
	fmt.Fprintf(w, "mode: %s\n", p.Mode)
	fmt.Fprintf(w, "gdpr_status: %s\n", label)
	fmt.Fprintln(w, "legal_notice: GDPR-aware tooling only; this is not legal advice or a compliance guarantee.")
	fmt.Fprintf(w, "lines_processed: %d\n", s.Lines)
}
