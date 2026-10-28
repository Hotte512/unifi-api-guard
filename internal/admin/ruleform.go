package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/Hotte512/unifi-api-guard/internal/rules"
)

const (
	// maxFormRules caps the number of rule cards a form submit may contain
	maxFormRules = 200
	// extraRuleCards is the number of empty cards shown for adding rules
	extraRuleCards = 2
	// customEndpoint is the endpoint select value for a path that is typed in
	customEndpoint = "custom"
)

type methodOption struct{ Value, Label string }

var methodOptions = []methodOption{
	{"GET", "lesen (GET)"},
	{"POST", "anlegen (POST)"},
	{"PUT", "ersetzen (PUT)"},
	{"PATCH", "ändern (PATCH)"},
	{"DELETE", "löschen (DELETE)"},
}

// ruleCard is one rule of the edit form, as shown or as submitted.
type ruleCard struct {
	N int
	// Endpoint is a catalog path, customEndpoint or "" (nothing chosen)
	Endpoint    string
	Path        string
	Methods     []string
	FilterField string
	// Patterns one per line
	Patterns string
	Delete   bool
}

func (c ruleCard) Num() int { return c.N + 1 }

func (c ruleCard) HasMethod(m string) bool { return slices.Contains(c.Methods, m) }

type endpointGroup struct {
	Name      string
	Endpoints []rules.Endpoint
}

func catalogGroups() []endpointGroup {
	var gs []endpointGroup
	for _, e := range rules.Catalog {
		i := slices.IndexFunc(gs, func(g endpointGroup) bool { return g.Name == e.Group })
		if i < 0 {
			gs = append(gs, endpointGroup{Name: e.Group})
			i = len(gs) - 1
		}
		gs[i].Endpoints = append(gs[i].Endpoints, e)
	}
	return gs
}

func catalogFilterFields() []string {
	var fs []string
	for _, e := range rules.Catalog {
		for _, f := range e.FilterFields {
			if !slices.Contains(fs, f) {
				fs = append(fs, f)
			}
		}
	}
	return fs
}

// cardsFromRules builds the form cards for a rule set plus empty cards for adding rules.
func cardsFromRules(rs []rules.Rule) []ruleCard {
	cards := make([]ruleCard, 0, len(rs)+extraRuleCards)
	for i, r := range rs {
		c := ruleCard{N: i, Endpoint: customEndpoint, Path: r.Path, Methods: r.Methods}
		if _, ok := rules.EndpointByPath(r.Path); ok {
			c.Endpoint = r.Path
		}
		if r.Filter != nil {
			c.FilterField = r.Filter.Field
			c.Patterns = strings.Join(r.Filter.Patterns, "\n")
		}
		cards = append(cards, c)
	}
	for i := 0; i < extraRuleCards && len(cards) < maxFormRules; i++ {
		cards = append(cards, ruleCard{N: len(cards)})
	}
	return cards
}

func lines(v string) []string {
	var out []string
	for _, l := range strings.Split(v, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// rule converts a card, empty reports a card without any input, which is skipped.
func (c ruleCard) rule() (r rules.Rule, empty bool, err error) {
	// the path input only counts for "Eigener Pfad", other endpoints must be catalog entries
	var path string
	switch {
	case c.Endpoint == customEndpoint:
		path = c.Path
	case c.Endpoint != "":
		e, ok := rules.EndpointByPath(c.Endpoint)
		if !ok {
			return r, false, errors.New("unbekannter Endpunkt.")
		}
		path = e.Path
	}
	patterns := lines(c.Patterns)
	hasFilter := c.FilterField != "" || len(patterns) > 0
	if path == "" {
		if len(c.Methods) == 0 && !hasFilter {
			return r, true, nil
		}
		return r, false, errors.New("bitte einen Endpunkt wählen oder „Eigener Pfad“ wählen und den Pfad eintragen.")
	}
	r.Path = path
	// known methods in a fixed order, unknown ones are kept so the validation rejects them
	for _, m := range methodOptions {
		if slices.Contains(c.Methods, m.Value) {
			r.Methods = append(r.Methods, m.Value)
		}
	}
	for _, m := range c.Methods {
		if !slices.Contains(r.Methods, m) {
			r.Methods = append(r.Methods, m)
		}
	}
	if len(r.Methods) == 0 {
		return r, false, errors.New("mindestens eine Methode erlauben.")
	}
	if hasFilter {
		if c.FilterField == "" || len(patterns) == 0 {
			return r, false, errors.New("ein Filter braucht ein Feld und mindestens ein Muster.")
		}
		r.Filter = &rules.Filter{Field: c.FilterField, Patterns: patterns}
	}
	if err := rules.Validate([]rules.Rule{r}); err != nil {
		return r, false, errors.New(strings.TrimPrefix(err.Error(), "rule 1: "))
	}
	return r, false, nil
}

// parseRuleForm reads the rule cards of the edit form. cards is nil when the form itself is unusable, otherwise it
// holds every submitted card for showing the form again.
func parseRuleForm(form url.Values) (cards []ruleCard, rs []rules.Rule, err error) {
	n, err := strconv.Atoi(strings.TrimSpace(form.Get("rule_count")))
	if err != nil || n < 0 {
		return nil, nil, errors.New("Regelformular unvollständig, bitte die Seite neu laden.")
	}
	if n > maxFormRules {
		return nil, nil, fmt.Errorf("Zu viele Regeln, höchstens %d sind im Formular möglich.", maxFormRules)
	}
	cards = make([]ruleCard, 0, n)
	rs = []rules.Rule{}
	for i := range n {
		p := "rule." + strconv.Itoa(i) + "."
		c := ruleCard{N: i, Endpoint: strings.TrimSpace(form.Get(p + "endpoint")),
			Path: strings.TrimSpace(form.Get(p + "path")), Methods: form[p+"methods"],
			FilterField: strings.TrimSpace(form.Get(p + "filter_field")), Patterns: form.Get(p + "patterns"),
			Delete: form.Get(p+"delete") != ""}
		cards = append(cards, c)
		if err != nil || c.Delete {
			continue
		}
		r, empty, rerr := c.rule()
		if rerr != nil {
			err = fmt.Errorf("Regel %d: %s", c.Num(), rerr.Error())
			continue
		}
		if !empty {
			rs = append(rs, r)
		}
	}
	if err != nil {
		return cards, nil, err
	}
	return cards, rs, nil
}

func decodeJSONRules(raw string) ([]rules.Rule, error) {
	var rs []rules.Rule
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rs); err != nil {
		return nil, err
	}
	if rs == nil {
		rs = []rules.Rule{}
	}
	return rs, nil
}

func rulesJSON(rs []rules.Rule) string {
	b, _ := json.MarshalIndent(rs, "", "  ")
	return string(b)
}

// editData is the template data of the edit page, cards are built from rs when nil.
func editData(c any, rs []rules.Rule, cards []ruleCard) map[string]any {
	if cards == nil {
		cards = cardsFromRules(rs)
	}
	return map[string]any{"Client": c, "Cards": cards, "RuleCount": len(cards), "MaxRules": maxFormRules,
		"Groups": catalogGroups(), "FilterFields": catalogFilterFields(), "Methods": methodOptions,
		"CustomEndpoint": customEndpoint, "RulesJSON": rulesJSON(rs), "RulesMode": "form"}
}
