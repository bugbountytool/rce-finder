// Command sastprobe runs the native Go static analyzer against a local module
// directory and prints source->sink findings. Local analysis only.
package main

import (
 "encoding/json"
 "fmt"
 "os"

 "github.com/bugbountytool/rce-finder/internal/analyze/gosast"
)

func main() {
 if len(os.Args) < 2 {
  fmt.Fprintln(os.Stderr, "usage: sastprobe <module-dir>")
  os.Exit(2)
 }
 a := gosast.New(os.Args[1])
 findings, err := a.Analyze()
 if err != nil {
  fmt.Fprintln(os.Stderr, "error:", err)
  os.Exit(1)
 }
 enc := json.NewEncoder(os.Stdout)
 enc.SetIndent("", "  ")
 for _, f := range findings {
  fmt.Fprintf(os.Stderr, "%s sink=%s line=%d complete=%v: %s\n", f.RuleID, f.SinkName, f.Sink.Line, f.Complete, f.Description)
  _ = enc.Encode(f)
 }
}
