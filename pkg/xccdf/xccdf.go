package xccdf

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	reportLibrary "github.com/rancher/security-scan/pkg/kb-summarizer/report"
)

const (
	xccdfNamespace     = "http://checklists.nist.gov/xccdf/1.2"
	xmlNamespace       = "http://www.w3.org/XML/1998/namespace"
	idPrefix           = "xccdf_compliance-operator"
	benchmarkIDSuffix  = "benchmark_kubernetes"
	testResultIDSuffix = "testresult_1"
	scoringSystem      = "urn:xccdf:scoring:default"
	checkSystem        = "urn:xccdf:check:manual"
	notApplicable      = "not-applicable"
)

// na returns "not-applicable" if s is empty.
func na(s string) string {
	if s == "" {
		return notApplicable
	}
	return s
}

// LangText represents an XCCDF element that carries an optional xml:lang attribute.
type LangText struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}

// Benchmark is the root XCCDF 1.2 element.
type Benchmark struct {
	XMLName     xml.Name          `xml:"Benchmark"`
	Xmlns       string            `xml:"xmlns,attr"`
	ID          string            `xml:"id,attr"`
	Resolved    string            `xml:"resolved,attr"`
	XMLLang     string            `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Style       string            `xml:"style,attr"`
	Status      Status            `xml:"status"`
	Title       LangText          `xml:"title"`
	Description LangText          `xml:"description"`
	Notices     []Notice          `xml:"notice"`
	FrontMatter LangText          `xml:"front-matter"`
	RearMatter  LangText          `xml:"rear-matter"`
	References  []Reference       `xml:"reference"`
	PlainTexts  []PlainText       `xml:"plain-text"`
	Platforms   []Platform        `xml:"platform"`
	Version     string            `xml:"version"`
	Metadata    BenchmarkMetadata `xml:"metadata"`
	Models      []Model           `xml:"model"`
	Profiles    []Profile         `xml:"Profile"`
	Groups      []Group           `xml:"Group"`
	TestResult  TestResult        `xml:"TestResult"`
}

// Status represents the XCCDF status element.
type Status struct {
	Date  string `xml:"date,attr"`
	Value string `xml:",chardata"`
}

// Notice represents an XCCDF notice element.
type Notice struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	ID    string `xml:"id,attr"`
	Value string `xml:",chardata"`
}

// Reference represents an XCCDF reference element at the Benchmark level.
type Reference struct {
	Href      string `xml:"href,attr"`
	Publisher string `xml:"publisher"`
	Source    string `xml:"source"`
}

// PlainText represents an XCCDF plain-text element.
type PlainText struct {
	ID    string `xml:"id,attr"`
	Value string `xml:",chardata"`
}

// Platform represents an XCCDF platform element.
type Platform struct {
	IDRef string `xml:"idref,attr"`
}

// BenchmarkMetadata represents the XCCDF metadata element and benchmark-level fields.
type BenchmarkMetadata struct {
	Creator      string `xml:"creator"`
	Publisher    string `xml:"publisher"`
	Contributor  string `xml:"contributor"`
	Source       string `xml:"source"`
	Description  string `xml:"-"`
	NoticeID     string `xml:"-"`
	Notice       string `xml:"-"`
	FrontMatter  string `xml:"-"`
	RearMatter   string `xml:"-"`
	ReferenceHref string `xml:"-"`
	PlainTextID  string `xml:"-"`
	PlainText    string `xml:"-"`
	Platform     string `xml:"-"`
	// BenchmarkID overrides the generated benchmark XML id attribute.
	BenchmarkID string `xml:"-"`
	// Title overrides the generated benchmark title element.
	Title string `xml:"-"`
	// Rule-level reference fields (same for all rules in a STIG benchmark).
	ReferenceTitle      string `xml:"-"`
	ReferenceType       string `xml:"-"`
	ReferenceSubject    string `xml:"-"`
	ReferenceIdentifier string `xml:"-"`
	// Check content ref fields shared across rules.
	CheckHref string `xml:"-"`
	CheckName string `xml:"-"`
	// Per-check STIG metadata keyed by STIG group ID (e.g. "V-254553").
	StigChecks map[string]StigCheckMetadata `xml:"-"`
	// ClusterName overrides the XCCDF <target> element. When empty, targets
	// are derived from node names in the scan report.
	ClusterName string `xml:"-"`
	// TargetAddresses are IP addresses of the scanned nodes for the XCCDF target-address elements.
	TargetAddresses []string `xml:"-"`
	// TargetFacts are XCCDF facts about the scanned nodes (hostname, IP, K8s version).
	TargetFacts []Fact `xml:"-"`
}

// StigCheckMetadata holds STIG-specific metadata for a single check group.
type StigCheckMetadata struct {
	RuleID   string
	Version  string
	Severity string
	FixID    string
	CheckID  string
	CCI      []string
}

// Model represents an XCCDF model element.
type Model struct {
	System string `xml:"system,attr"`
}

// Profile represents an XCCDF Profile element.
type Profile struct {
	ID          string          `xml:"id,attr"`
	Title       LangText        `xml:"title"`
	Description LangText        `xml:"description"`
	Selects     []ProfileSelect `xml:"select"`
}

// ProfileSelect represents a select element within a Profile.
type ProfileSelect struct {
	IDRef    string `xml:"idref,attr"`
	Selected string `xml:"selected,attr"`
}

// Group represents an XCCDF Group element containing related rules.
type Group struct {
	ID          string   `xml:"id,attr"`
	Title       LangText `xml:"title"`
	Description LangText `xml:"description"`
	Rules       []Rule   `xml:"Rule"`
}

// Rule represents an XCCDF Rule element.
type Rule struct {
	ID          string          `xml:"id,attr"`
	Selected    string          `xml:"selected,attr"`
	Weight      string          `xml:"weight,attr"`
	Role        string          `xml:"role,attr"`
	Severity    string          `xml:"severity,attr"`
	Version     string          `xml:"version"`
	Title       LangText        `xml:"title"`
	Description LangText        `xml:"description"`
	References  []RuleReference `xml:"reference"`
	Idents      []Ident         `xml:"ident"`
	FixText     RuleFixText     `xml:"fixtext"`
	Fix         RuleFix         `xml:"fix"`
	Check       RuleCheck       `xml:"check"`
}

// RuleReference represents a reference element within a Rule.
type RuleReference struct {
	Title      string `xml:"title"`
	Subject    string `xml:"subject"`
	Publisher  string `xml:"publisher"`
	Type       string `xml:"type"`
	Identifier string `xml:"identifier"`
}

// RuleFixText represents the fixtext element within a Rule.
type RuleFixText struct {
	Lang   string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	FixRef string `xml:"fixref,attr"`
	Value  string `xml:",chardata"`
}

// RuleFix represents the fix element within a Rule.
type RuleFix struct {
	ID    string `xml:"id,attr"`
	Value string `xml:",chardata"`
}

// RuleCheck represents the check element within a Rule.
type RuleCheck struct {
	System          string          `xml:"system,attr"`
	CheckContentRef CheckContentRef `xml:"check-content-ref"`
	CheckContent    string          `xml:"check-content"`
}

// CheckContentRef represents a check-content-ref element.
type CheckContentRef struct {
	Name string `xml:"name,attr"`
	Href string `xml:"href,attr"`
}

// BenchmarkRef represents the benchmark reference element within a TestResult.
type BenchmarkRef struct {
	Href string `xml:"href,attr"`
	ID   string `xml:"id,attr"`
}

// Fact represents a single fact within target-facts.
type Fact struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

// TargetFacts represents the target-facts element in a TestResult.
type TargetFacts struct {
	Facts []Fact `xml:"fact"`
}

// TestIdentity represents the identity element within a TestResult.
type TestIdentity struct {
	Authenticated bool   `xml:"authenticated,attr"`
	Privileged    bool   `xml:"privileged,attr"`
	Value         string `xml:",chardata"`
}

// TestResult represents the XCCDF TestResult element containing all rule results.
type TestResult struct {
	ID              string       `xml:"id,attr"`
	StartTime       string       `xml:"start-time,attr"`
	EndTime         string       `xml:"end-time,attr"`
	Version         string       `xml:"version,attr"`
	TestSystem      string       `xml:"test-system,attr"`
	BenchmarkRef    BenchmarkRef `xml:"benchmark"`
	Title           string       `xml:"title"`
	Identity        TestIdentity `xml:"identity"`
	Targets         []string     `xml:"target"`
	TargetAddresses []string     `xml:"target-address"`
	TargetFacts     TargetFacts  `xml:"target-facts"`
	Platforms       []Platform   `xml:"platform"`
	RuleResults     []RuleResult `xml:"rule-result"`
	Score           Score        `xml:"score"`
}

// Score represents the XCCDF score element.
type Score struct {
	System  string `xml:"system,attr"`
	Maximum string `xml:"maximum,attr"`
	Value   string `xml:",chardata"`
}

// Ident represents an XCCDF ident element.
type Ident struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

// RuleResultCheck represents the check element within a rule-result.
type RuleResultCheck struct {
	System          string          `xml:"system,attr"`
	CheckContentRef CheckContentRef `xml:"check-content-ref"`
	CheckContent    string          `xml:"check-content"`
}

// RuleResult represents the result of a single rule evaluation.
type RuleResult struct {
	IDRef    string          `xml:"idref,attr"`
	Role     string          `xml:"role,attr"`
	Time     string          `xml:"time,attr"`
	Severity string          `xml:"severity,attr"`
	Version  string          `xml:"version,attr"`
	Weight   string          `xml:"weight,attr"`
	Idents   []Ident         `xml:"ident"`
	Result   string          `xml:"result"`
	Check    RuleResultCheck `xml:"check"`
}

// ResultSummary holds rule-result outcome counts from a parsed XCCDF TestResult.
type ResultSummary struct {
	Total         int
	Pass          int
	Fail          int
	Skip          int
	Warn          int
	NotApplicable int
}

// ParseXCCDF parses an XCCDF 1.2 XML document into a Benchmark.
func ParseXCCDF(data []byte) (*Benchmark, error) {
	var b Benchmark
	if err := xml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("error parsing XCCDF: %w", err)
	}
	return &b, nil
}

// SummarizeResults tallies rule-result outcomes from the parsed Benchmark's TestResult.
func SummarizeResults(b *Benchmark) ResultSummary {
	var s ResultSummary
	for _, rr := range b.TestResult.RuleResults {
		s.Total++
		switch strings.ToLower(strings.TrimSpace(rr.Result)) {
		case "pass":
			s.Pass++
		case "fail":
			s.Fail++
		case "notapplicable":
			s.NotApplicable++
		case "notselected":
			s.Skip++
		case "informational":
			s.Warn++
		default:
			s.Warn++
		}
	}
	return s
}

// ruleID constructs a stable XCCDF rule ID from a check ID.
func ruleID(checkID string) string {
	safe := strings.ReplaceAll(checkID, " ", "_")
	return fmt.Sprintf("%s_rule_%s", idPrefix, safe)
}

// groupID constructs a stable XCCDF group ID from a group ID.
func groupID(gid string) string {
	safe := strings.ReplaceAll(gid, " ", "_")
	return fmt.Sprintf("%s_group_%s", idPrefix, safe)
}

// mapResult converts a report.State to an XCCDF result string.
func mapResult(state reportLibrary.State) string {
	switch state {
	case reportLibrary.Pass:
		return "pass"
	case reportLibrary.Fail:
		return "fail"
	case reportLibrary.Skip:
		return "notselected"
	case reportLibrary.Warn:
		return "informational"
	case reportLibrary.NotApplicable:
		return "notapplicable"
	default:
		return "informational"
	}
}

// severity returns an XCCDF severity based on whether a check is scored.
func severity(scored bool) string {
	if scored {
		return "medium"
	}
	return "low"
}

// ruleWeight returns the XCCDF weight for a rule based on whether it is scored.
func ruleWeight(scored bool) string {
	if scored {
		return "10"
	}
	return "0"
}

// ruleRole returns the XCCDF role for a rule based on whether it is scored.
func ruleRole(scored bool) string {
	if scored {
		return "full"
	}
	return "unscored"
}

// fixID constructs a stable fix ID from a rule ID.
func fixID(checkID string) string {
	return ruleID(checkID) + "_fix"
}

// profileID constructs the XCCDF profile ID from a benchmark version.
func profileID(benchmarkVersion string) string {
	safe := strings.ReplaceAll(benchmarkVersion, " ", "_")
	return fmt.Sprintf("%s_profile_%s", idPrefix, safe)
}

// stigGroupID extracts the STIG group ID prefix from a check ID.
// e.g. "V-254553-TLS-apiserver" -> "V-254553", "V-254554" -> "V-254554".
func stigGroupID(checkID string) string {
	parts := strings.SplitN(checkID, "-", 3)
	if len(parts) >= 2 {
		return parts[0] + "-" + parts[1]
	}
	return checkID
}

// effectiveRuleID returns the XCCDF rule id to use for a check.
// When STIG metadata is present it uses stig.RuleID as the base, appending the
// sub-check component so that sibling checks within one STIG group remain unique.
// e.g. group V-254553, check V-254553-TLS-apiserver → "SV-254553r1016525_rule_TLS-apiserver"
// e.g. group V-254554, check V-254554 (no sub-suffix) → "SV-254554r1043176_rule"
func effectiveRuleID(stig StigCheckMetadata, checkID string) string {
	if stig.RuleID == "" {
		return ruleID(checkID)
	}
	gid := stigGroupID(checkID)
	if checkID == gid {
		return stig.RuleID
	}
	suffix := strings.TrimPrefix(checkID, gid+"-")
	return stig.RuleID + "_" + suffix
}

// lookupStig returns the StigCheckMetadata for a check ID, or an empty struct.
func lookupStig(metadata BenchmarkMetadata, checkID string) StigCheckMetadata {
	if metadata.StigChecks == nil {
		return StigCheckMetadata{}
	}
	if s, ok := metadata.StigChecks[stigGroupID(checkID)]; ok {
		return s
	}
	return StigCheckMetadata{}
}

// stigSeverity returns the severity from STIG metadata if present, else derives it from scored.
func stigSeverity(stigSev string, scored bool) string {
	if stigSev != "" {
		return stigSev
	}
	return severity(scored)
}

// stigIdents converts a CCI list to XCCDF Ident elements.
func stigIdents(ccis []string) []Ident {
	if len(ccis) == 0 {
		return []Ident{{System: notApplicable, Value: notApplicable}}
	}
	idents := make([]Ident, len(ccis))
	for i, cci := range ccis {
		idents[i] = Ident{System: "http://cyber.mil/cci", Value: cci}
	}
	return idents
}

// buildRuleReferences constructs the rule-level reference list from benchmark metadata.
func buildRuleReferences(metadata BenchmarkMetadata) []RuleReference {
	return []RuleReference{{
		Title:      na(metadata.ReferenceTitle),
		Publisher:  na(metadata.Publisher),
		Type:       na(metadata.ReferenceType),
		Subject:    na(metadata.ReferenceSubject),
		Identifier: na(metadata.ReferenceIdentifier),
	}}
}

// collectTargets returns a deduplicated list of node names from the report.
func collectTargets(r *reportLibrary.Report) []string {
	seen := map[string]bool{}
	var targets []string
	for _, nodes := range r.Nodes {
		for _, n := range nodes {
			if !seen[n] {
				seen[n] = true
				targets = append(targets, n)
			}
		}
	}
	if len(targets) == 0 {
		targets = []string{notApplicable}
	}
	return targets
}

// collectTargetAddresses returns node IP addresses from metadata, falling back to not-applicable.
func collectTargetAddresses(metadata BenchmarkMetadata) []string {
	if len(metadata.TargetAddresses) > 0 {
		return metadata.TargetAddresses
	}
	return []string{notApplicable}
}

// collectTargetFacts returns XCCDF facts from metadata, falling back to a single not-applicable fact.
func collectTargetFacts(metadata BenchmarkMetadata) []Fact {
	if len(metadata.TargetFacts) > 0 {
		return metadata.TargetFacts
	}
	return []Fact{{Name: notApplicable, Type: "string", Value: notApplicable}}
}

// GenerateXCCDF converts a parsed report.Report into an XCCDF 1.2 XML document.
// All optional fields that are not populated by the scan are set to "not-applicable".
func GenerateXCCDF(r *reportLibrary.Report, benchmarkVersion string, metadata BenchmarkMetadata) ([]byte, error) {
	now := time.Now().UTC()
	timeStr := now.Format("2006-01-02T15:04:05Z")
	dateStr := now.Format("2006-01-02")

	benchmarkID := fmt.Sprintf("%s_%s", idPrefix, benchmarkIDSuffix)
	if metadata.BenchmarkID != "" {
		benchmarkID = metadata.BenchmarkID
	}

	benchmarkTitle := fmt.Sprintf("Kubernetes CIS Benchmark %s", benchmarkVersion)
	if metadata.Title != "" {
		benchmarkTitle = metadata.Title
	}

	benchmark := Benchmark{
		Xmlns:    xccdfNamespace,
		ID:       benchmarkID,
		Resolved: "1",
		XMLLang:  "en",
		Style:    "",
		Status: Status{
			Date:  dateStr,
			Value: "complete",
		},
		Title:       LangText{Value: benchmarkTitle},
		Description: LangText{Value: na(metadata.Description)},
		Notices:     []Notice{{ID: na(metadata.NoticeID), Value: na(metadata.Notice)}},
		FrontMatter: LangText{Value: na(metadata.FrontMatter)},
		RearMatter:  LangText{Value: na(metadata.RearMatter)},
		References:  []Reference{{Href: na(metadata.ReferenceHref), Publisher: na(metadata.Publisher), Source: na(metadata.Source)}},
		PlainTexts:  []PlainText{{ID: na(metadata.PlainTextID), Value: na(metadata.PlainText)}},
		Platforms:   []Platform{{IDRef: na(metadata.Platform)}},
		Version:     na(r.Version),
		Metadata: BenchmarkMetadata{
			Creator:     na(metadata.Creator),
			Publisher:   na(metadata.Publisher),
			Contributor: na(metadata.Contributor),
			Source:      na(metadata.Source),
		},
		Models: []Model{{System: scoringSystem}},
		Profiles: []Profile{{
			ID:          profileID(benchmarkVersion),
			Title:       LangText{Value: benchmarkTitle},
			Description: LangText{Value: na(metadata.Description)},
			Selects:     []ProfileSelect{},
		}},
	}

	var ruleResults []RuleResult

	for _, group := range r.Results {
		g := Group{
			ID:          na(group.ID),
			Title:       LangText{Value: na(group.Text)},
			Description: LangText{Value: na(group.Text)},
		}
		for _, check := range group.Checks {
			stig := lookupStig(metadata, check.ID)
			effectiveID := effectiveRuleID(stig, check.ID)

			ruleFixID := fixID(check.ID)
			if stig.FixID != "" {
				ruleFixID = stig.FixID
			}

			ruleCheckSystem := checkSystem
			if stig.CheckID != "" {
				ruleCheckSystem = stig.CheckID
			}

			checkHref := na(metadata.CheckHref)
			checkName := na(metadata.CheckName)

			rule := Rule{
				ID:          effectiveID,
				Selected:    "true",
				Weight:      ruleWeight(check.Scored),
				Role:        ruleRole(check.Scored),
				Severity:    stigSeverity(stig.Severity, check.Scored),
				Version:     na(stig.Version),
				Title:       LangText{Value: na(fmt.Sprintf("%s %s", check.ID, check.Text))},
				Description: LangText{Value: na(check.Text)},
				References:  buildRuleReferences(metadata),
				Idents:      stigIdents(stig.CCI),
				FixText: RuleFixText{
					FixRef: ruleFixID,
					Value:  na(check.Remediation),
				},
				Fix: RuleFix{
					ID:    ruleFixID,
					Value: "",
				},
				Check: RuleCheck{
					System:          ruleCheckSystem,
					CheckContentRef: CheckContentRef{Name: checkName, Href: checkHref},
					CheckContent:    na(check.Audit),
				},
			}
			g.Rules = append(g.Rules, rule)

			ruleResults = append(ruleResults, RuleResult{
				IDRef:    effectiveID,
				Role:     ruleRole(check.Scored),
				Time:     timeStr,
				Severity: stigSeverity(stig.Severity, check.Scored),
				Version:  na(stig.Version),
				Weight:   ruleWeight(check.Scored),
				Idents:   stigIdents(stig.CCI),
				Result:   mapResult(check.State),
				Check: RuleResultCheck{
					System:          ruleCheckSystem,
					CheckContentRef: CheckContentRef{Name: checkName, Href: checkHref},
					CheckContent:    na(check.Audit),
				},
			})
		}
		benchmark.Groups = append(benchmark.Groups, g)
	}

	if len(benchmark.Groups) == 0 {
		benchmark.Groups = []Group{{
			ID:          notApplicable,
			Title:       LangText{Value: notApplicable},
			Description: LangText{Value: notApplicable},
		}}
	}

	var scoreStr string
	if r.Total > 0 {
		scoreStr = fmt.Sprintf("%.1f", float64(r.Pass)/float64(r.Total)*100)
	} else {
		scoreStr = "0.0"
	}

	if len(ruleResults) == 0 {
		ruleResults = []RuleResult{{
			IDRef:    notApplicable,
			Role:     notApplicable,
			Time:     timeStr,
			Severity: notApplicable,
			Version:  notApplicable,
			Weight:   notApplicable,
			Idents:   []Ident{{System: notApplicable, Value: notApplicable}},
			Result:   notApplicable,
			Check: RuleResultCheck{
				System:          notApplicable,
				CheckContentRef: CheckContentRef{Name: notApplicable, Href: notApplicable},
				CheckContent:    notApplicable,
			},
		}}
	}

	targets := collectTargets(r)
	if metadata.ClusterName != "" {
		targets = []string{metadata.ClusterName}
	}
	benchmark.TestResult = TestResult{
		ID:         fmt.Sprintf("%s_%s", idPrefix, testResultIDSuffix),
		StartTime:  timeStr,
		EndTime:    timeStr,
		Version:    benchmarkVersion,
		TestSystem: idPrefix,
		BenchmarkRef: BenchmarkRef{
			Href: "#" + benchmarkID,
			ID:   benchmarkID,
		},
		Title: benchmarkTitle,
		Identity: TestIdentity{
			Authenticated: true,
			Privileged:    true,
			Value:         "compliance-scan-serviceaccount",
		},
		Targets:         targets,
		TargetAddresses: collectTargetAddresses(metadata),
		TargetFacts: TargetFacts{
			Facts: collectTargetFacts(metadata),
		},
		Platforms:   []Platform{{IDRef: na(metadata.Platform)}},
		RuleResults: ruleResults,
		Score: Score{
			System:  scoringSystem,
			Maximum: "100.0",
			Value:   scoreStr,
		},
	}

	output, err := xml.MarshalIndent(benchmark, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshalling XCCDF benchmark: %w", err)
	}

	return append([]byte(xml.Header), output...), nil
}

// FromJSON parses raw JSON scan output and returns an XCCDF 1.2 XML document.
func FromJSON(outputBytes []byte, benchmarkVersion string, metadata BenchmarkMetadata) ([]byte, error) {
	r, err := reportLibrary.Get(outputBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing scan output: %w", err)
	}
	if r == nil {
		return nil, fmt.Errorf("empty scan report")
	}
	return GenerateXCCDF(r, benchmarkVersion, metadata)
}
