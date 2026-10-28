package rules

// Template is a predefined rule set for a common use case.
type Template struct {
	ID          string
	Name        string
	Description string
	// NeedsDomains: the template restricts objects to domains the user enters
	NeedsDomains bool
	build        func(domains []string) []Rule
}

// Rules builds the rule set, domains are only used by templates with NeedsDomains.
func (t Template) Rules(domains []string) []Rule { return t.build(domains) }

var get = []string{"GET"}

// Templates available in the admin ui.
var Templates = []Template{
	{
		ID:           "dns-records",
		Name:         "Lokale DNS-Einträge (z. B. NPMplus)",
		Description:  "Sites lesen, DNS-Policies der angegebenen Domains lesen, anlegen, ändern und löschen. Sonst nichts.",
		NeedsDomains: true,
		build: func(domains []string) []Rule {
			f := &Filter{Field: "domain", Patterns: domains}
			return []Rule{
				{Methods: get, Path: "sites"},
				{Methods: []string{"GET", "POST"}, Path: "sites/*/dns/policies", Filter: f},
				{Methods: []string{"GET", "PUT", "DELETE"}, Path: "sites/*/dns/policies/*", Filter: f},
			}
		},
	},
	{
		ID:          "read-only",
		Name:        "Nur lesen",
		Description: "Alle GET-Anfragen der Network-API, keine Änderungen.",
		build: func([]string) []Rule {
			return []Rule{{Methods: get, Path: "**"}}
		},
	},
	{
		ID:          "devices-clients-read",
		Name:        "Geräte und Clients lesen (z. B. Home Assistant)",
		Description: "Sites, Geräte und Clients lesen. Keine Änderungen, keine Firewall- oder Netzwerkeinstellungen.",
		build: func([]string) []Rule {
			return []Rule{
				{Methods: get, Path: "info"},
				{Methods: get, Path: "sites"},
				{Methods: get, Path: "sites/*/devices/**"},
				{Methods: get, Path: "sites/*/devices"},
				{Methods: get, Path: "sites/*/clients/**"},
				{Methods: get, Path: "sites/*/clients"},
			}
		},
	},
	{
		ID:          "custom",
		Name:        "Eigene Regeln",
		Description: "Leere Regelliste (alles verboten), Regeln danach selbst eintragen.",
		build:       func([]string) []Rule { return []Rule{} },
	},
}

// TemplateByID returns the template or false.
func TemplateByID(id string) (Template, bool) {
	for _, t := range Templates {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}
