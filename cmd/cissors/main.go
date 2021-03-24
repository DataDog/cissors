package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/DataDog/cissors"

	"github.com/ledongthuc/pdf"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v3"
)

var (
	verbose  = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()
	inFile   = kingpin.Arg("file", "File to parse.").Required().String()
	outFile  = kingpin.Flag("out", "Output to file.").Short('o').String()
	format   = kingpin.Flag("format", "Format for the output - default YAML").String()
	idPrefix = kingpin.Flag("id-prefix", "ID prefix for rules.").String()
)

var (
	pageMarkerRegex = regexp.MustCompile(`^([\d]+\s+\|\s+Page)`)

	// An id, eg. 1 or 1.2 or 1.21.1
	id = `(\d+(?:\.\d+)*)`
	// A name, then either (Automated), (Manual), (Scored) or (Not Scored),
	nameAndRuleType = `(.*)(?:\((Automated|Manual|Scored|Not Scored)\))`

	// Page number of a rule, and id of the next
	titlesSeparatorRegex = regexp.MustCompile(`(\d+)\s` + id)

	normalRuleTitleRegex = regexp.MustCompile(id + nameAndRuleType)
	majorRuleTitleRegex  = regexp.MustCompile(id + `([^\.]+)\.+`)

	sectionRegex = regexp.MustCompile(
		`((Profile Applicability|Description|Rationale|Audit|Remediation|Impact|Default\sValue|References|CIS\sControls)\:\s+)`,
	)

	whitespace    = regexp.MustCompile(`\s+`)
	nonASCIIRegex = regexp.MustCompile(`[[:^ascii:]]`)
)

func main() {
	kingpin.Parse()
	_, reader, err := pdf.Open(*inFile)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Failed to parse PDF: %v", err)
	}

	fmt.Print("✂️  You are now running with CISsors\n\n")
	fmt.Print("✂️  Skillfully cutting your CIS benchmark️\n\n")
	startPage := 0

	ruleIDToName := map[string]string{}
	ruleCount := 0
	matchingTitleRegString := []string{}

	// First pass to find the titles (using the table of contents)
	walkPages(reader, 2, reader.NumPage(), func(page int, content string) bool {
		if *verbose {
			fmt.Printf("✂️  Looking for titles in page %d\n", page)
		}

		// We split using a 'separator' between two titles - the page number at the end of the title
		// and the id at the beginning on the next one
		titles := []string{}
		titlesSeparator := titlesSeparatorRegex.FindAllStringSubmatchIndex(content, -1)
		startIndex := 0
		for i := 0; i < len(titlesSeparator); i++ {
			// index 3 is the end of the page number
			titles = append(titles, content[startIndex:titlesSeparator[i][3]])
			// index 4 is the beginning of the id
			startIndex = titlesSeparator[i][4]
		}
		if len(titlesSeparator) > 0 {
			// Pick the last title as well
			titles = append(titles, content[startIndex:])
		}

		// The table of contents is finished
		if len(ruleIDToName) != 0 && len(titles) == 0 {
			// we will start scanning for rules from this page onward
			startPage = page
			return false
		}

		for _, title := range titles {
			id, name, isActualRule, _, err := splitTitle(title)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}

			if *verbose {
				fmt.Printf("id: %s - name: %s, actualRule: %t\n", id, name, isActualRule)
			}

			ruleIDToName[id] = name
			if isActualRule {
				matchingTitleRegString = append(matchingTitleRegString, regexp.QuoteMeta(id))
				ruleCount++
			}
		}
		return true
	})

	fmt.Printf("✂️  Found %d rules\n\n", ruleCount)

	var (
		nextRuleContent string
		nextRuleTitle   string
		rules           []*cissors.Rule
	)

	// We build a regex that's more precise than normalRuleTitleRegex, as it matches on the actual rule ids we expect
	ruleTitleExtractRegex := regexp.MustCompile("(" + strings.Join(matchingTitleRegString, "|") + `)\s` + nameAndRuleType)

	walkPages(reader, startPage, reader.NumPage(), func(page int, content string) bool {
		if *verbose {
			fmt.Printf("✂️  Looking for rules in page %d\n", page)
		}

		r := ruleTitleExtractRegex.FindStringSubmatchIndex(content)

		if len(r) == 0 {
			if nextRuleTitle != "" {
				// Collect the next rule content
				nextRuleContent += "\n" + content
			}
			return true
		}

		if nextRuleTitle != "" {
			// Extract and append the rule
			if *verbose {
				fmt.Printf("-- Rule content for %s --\n", nextRuleTitle)
				fmt.Println(nextRuleContent)
				fmt.Printf("-- End rule content for %s --\n", nextRuleTitle)
			}

			if rule, err := extractRule(nextRuleTitle, nextRuleContent); err == nil {
				rule.Location = getRuleLocation(ruleIDToName, rule.ID)
				rules = append(rules, rule)
				ruleCount--
				if ruleCount == 0 {
					fmt.Printf("✂️  Done extracting rules\n\n")
					return false
				}
			} else {
				fmt.Fprintf(os.Stderr, "Failed to extract rule: %v\n", err)
			}
		}

		nextRuleTitle = content[r[0]:r[1]]
		nextRuleContent = content[r[1]:]
		return true
	})

	var output = ""
	if *format == "json" {
		buf := new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)

		err := enc.Encode(&rules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to serialize as JSON: %v\n", err)
			return
		}

		var out bytes.Buffer
		json.Indent(&out, buf.Bytes(), "", "    ")
		output = out.String()
	} else {
		yamlData, err := yaml.Marshal(&rules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to serialize as YAML: %v\n", err)
			return
		}

		output = fmt.Sprintf("---\n%s", string(yamlData))
	}

	fmt.Print("✂️️️  All done! Enjoy your masterpiece!\n\n")

	f := os.Stdout
	if *outFile != "" {
		file, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open file %v", err)
			return
		}
		defer file.Close()
		f = file
	}

	fmt.Fprint(f, output)
}

func extractRule(title, content string) (*cissors.Rule, error) {
	id, name, _, ruleType, err := splitTitle(title)
	if err != nil {
		return nil, fmt.Errorf("Malformed rule title %s: %w", title, err)
	}

	// Extract rule sections after the title
	sections := findNamedValuesByRegex(content, sectionRegex)
	if len(sections) == 0 {
		return nil, fmt.Errorf("No valid sections for rule %s", title)
	}

	rule := &cissors.Rule{
		ID:       *idPrefix + id,
		RuleType: ruleType,
		Name:     name,
		Sections: map[string]string{},
	}

	for _, section := range sections {
		rule.Sections[sectionKeyName(section.name)] = sectionContent(section.value)
	}
	return rule, nil
}

func walkPages(reader *pdf.Reader, start, end int, pageFn func(page int, s string) bool) {
	for i := start; i < end; i++ {
		p := reader.Page(i)

		content, err := p.GetPlainText(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to extract page %d as plain text: %v", i, err)
			continue
		}

		content, ok := cutPageMarker(content)
		if !ok {
			fmt.Fprintf(os.Stderr, "Failed to extract page marker on page %d", i)
			continue
		}

		if !pageFn(i, content) {
			break
		}
	}
}

func cutPageMarker(s string) (string, bool) {
	// Chop the page marker
	pm := pageMarkerRegex.FindStringSubmatchIndex(s)
	if len(pm) == 0 {
		return "", false
	}
	return s[pm[1]:], true
}

// Split a title into its id, its name, whether it's an actual rule or group of rules
// and it's type
func splitTitle(title string) (id, name string, isActualRule bool, ruleType cissors.RuleType, err error) {
	titleParts := normalRuleTitleRegex.FindStringSubmatch(title)
	if titleParts != nil {
		// Actual rule
		isActualRule = true
		id = titleParts[1]
		name = strings.TrimSpace(replaceWhitespaces(titleParts[2]))
		ruleType = (cissors.RuleType)(titleParts[3])
		return
	}

	// May be a group of rules
	titleParts = majorRuleTitleRegex.FindStringSubmatch(title)
	if titleParts != nil {
		isActualRule = false
		id = titleParts[1]
		name = strings.TrimSpace(replaceWhitespaces(titleParts[2]))
		return
	}

	err = fmt.Errorf("Failed to parse the title as either a rule or a group of rules: %s", title)
	return
}

type namedValue struct {
	name  string
	value string
}

func findNamedValuesByRegex(s string, r *regexp.Regexp) []namedValue {
	hits := r.FindAllStringSubmatchIndex(s, -1)
	var result []namedValue

	for h := 0; h < len(hits); h++ {
		hit := hits[h]
		name := s[hit[0]:hit[1]]
		var value string
		if h != len(hits)-1 {
			value = s[hit[1]:hits[h+1][0]]
		} else {
			value = s[hit[1]:]
		}

		result = append(result, namedValue{
			name:  name,
			value: value,
		})

	}
	return result
}

func sectionKeyName(name string) string {
	key := strings.ToLower(strings.Trim(name, " :\t\n"))
	return whitespace.ReplaceAllString(key, "_")
}

func sectionContent(content string) string {
	content = strings.TrimSpace(nonASCIIRegex.ReplaceAllLiteralString(content, ""))
	return replaceWhitespaces(content)
}

func replaceWhitespaces(content string) string {
	return whitespace.ReplaceAllString(content, " ")
}

func getRuleLocation(ruleIDToName map[string]string, ruleID string) []cissors.Location {
	var loc []cissors.Location
	const sep = "."
	parts := strings.Split(ruleID, sep)
	for i := 0; i < len(parts)-1; i++ {
		parentID := strings.Join(parts[:i+1], sep)
		if parentName, ok := ruleIDToName[parentID]; ok {
			loc = append(loc, cissors.Location{
				ID:   *idPrefix + parentID,
				Name: parentName,
			})
		}
	}
	return loc
}
