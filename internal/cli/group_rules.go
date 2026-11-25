package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/adrianmross/oci-idm/internal/grouprules"
)

func runGroupRules(verb string, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet(verb+" group-rules", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var file, service, out string
	var execute, confirm bool
	addFileFlags(flags, &file, "group template or reviewed plan; - reads stdin")
	if verb == "plan" {
		flags.StringVar(&service, "oci-context-service", "", "fill unset target fields from this exact token service")
	} else {
		flags.BoolVar(&execute, "execute", false, "apply the reviewed plan")
		flags.BoolVar(&confirm, "confirm", false, "confirm the reviewed target and membership changes")
		flags.StringVar(&out, "out", "oci-idm-group-rules-apply", "directory for OCI request payloads")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || file == "" {
		return fmt.Errorf("%s group-rules requires -f <file> and no positional arguments", verb)
	}
	var in io.Reader = stdinReader
	if file != "-" {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	decoder := json.NewDecoder(in)
	decoder.DisallowUnknownFields()
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	var plan grouprules.Plan
	if verb == "plan" {
		var t grouprules.Template
		if err := decoder.Decode(&t); err != nil {
			return err
		}
		if service != "" {
			d := loadOCIContextDefaults("oci-context", service)
			if d.ServiceName != service || d.Issuer == "" {
				return fmt.Errorf("OCI context did not resolve service %q", service)
			}
			if t.Target.Issuer == "" {
				t.Target.Issuer = d.Issuer
			}
			if t.Target.Scope == "" {
				t.Target.Scope = d.Scope
			}
			if t.Target.Profile == "" {
				t.Target.Profile = d.Profile
			}
			if t.Target.ConfigFile == "" {
				t.Target.ConfigFile = d.OCIConfigPath
			}
			if t.Target.Region == "" {
				t.Target.Region = d.Region
			}
		}
		var err error
		plan, err = grouprules.Build(t)
		if err != nil {
			return err
		}
	} else if err := decoder.Decode(&plan); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("expected exactly one JSON document")
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if !execute {
		return enc.Encode(plan)
	}
	if !confirm {
		return fmt.Errorf("--execute requires --confirm")
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("--out must be a directory")
	}
	steps, err := grouprules.Execute(plan, out, grouprules.Runner(runCommand))
	if printErr := enc.Encode(steps); printErr != nil && err == nil {
		return printErr
	}
	return err
}
