package rules

// Endpoint describes one path of the UniFi Network Integration API for the rule form in the admin ui.
type Endpoint struct {
	// Group for the select box, e.g. "DNS"
	Group string
	// Name shown to the user, e.g. "DNS-Policies (Liste / anlegen)"
	Name string
	// Path in rule syntax, relative to /proxy/network/integration/v1, e.g. "sites/*/dns/policies"
	Path string
	// Methods the api supports on the path
	Methods []string
	// FilterFields are string fields of the objects that make sense as a rule filter, e.g. "domain"
	FilterFields []string
}

// Catalog lists the known endpoints, grouped and in display order.
// Source: UniFi Network Integration API docs, version 10.1.84 (hand-curated, one entry per path).
var Catalog = []Endpoint{
	// Allgemein
	{Group: "Allgemein", Name: "Anwendungsinfo", Path: "info", Methods: []string{"GET"}},
	{Group: "Allgemein", Name: "Sites (Liste)", Path: "sites", Methods: []string{"GET"}},
	{Group: "Allgemein", Name: "Geräte im Adoptions-Wartezustand", Path: "pending-devices", Methods: []string{"GET"}},
	{Group: "Allgemein", Name: "Länder (Liste)", Path: "countries", Methods: []string{"GET"}},
	{Group: "Allgemein", Name: "DPI-Kategorien", Path: "dpi/categories", Methods: []string{"GET"}},
	{Group: "Allgemein", Name: "DPI-Anwendungen", Path: "dpi/applications", Methods: []string{"GET"}},
	// Geräte
	{Group: "Geräte", Name: "Geräte (Liste / adoptieren)", Path: "sites/*/devices", Methods: []string{"GET", "POST"}, FilterFields: []string{"macAddress"}},
	{Group: "Geräte", Name: "Gerät (einzeln / entfernen)", Path: "sites/*/devices/*", Methods: []string{"GET", "DELETE"}, FilterFields: []string{"name", "macAddress"}},
	{Group: "Geräte", Name: "Gerät: Aktionen", Path: "sites/*/devices/*/actions", Methods: []string{"POST"}},
	{Group: "Geräte", Name: "Gerät: Port-Aktionen", Path: "sites/*/devices/*/interfaces/ports/*/actions", Methods: []string{"POST"}},
	{Group: "Geräte", Name: "Gerät: Statistiken (aktuell)", Path: "sites/*/devices/*/statistics/latest", Methods: []string{"GET"}},
	{Group: "Geräte", Name: "Geräte-Tags (Liste)", Path: "sites/*/device-tags", Methods: []string{"GET"}},
	// Clients
	{Group: "Clients", Name: "Clients (Liste)", Path: "sites/*/clients", Methods: []string{"GET"}},
	{Group: "Clients", Name: "Client (einzeln)", Path: "sites/*/clients/*", Methods: []string{"GET"}},
	{Group: "Clients", Name: "Client: Aktionen", Path: "sites/*/clients/*/actions", Methods: []string{"POST"}},
	// Netzwerke
	{Group: "Netzwerke", Name: "Netzwerke (Liste / anlegen)", Path: "sites/*/networks", Methods: []string{"GET", "POST"}, FilterFields: []string{"name"}},
	{Group: "Netzwerke", Name: "Netzwerk (einzeln)", Path: "sites/*/networks/*", Methods: []string{"GET", "PUT", "DELETE"}, FilterFields: []string{"name"}},
	{Group: "Netzwerke", Name: "Netzwerk: Verwendungen", Path: "sites/*/networks/*/references", Methods: []string{"GET"}},
	// WLAN
	{Group: "WLAN", Name: "WLAN-Broadcasts (Liste / anlegen)", Path: "sites/*/wifi/broadcasts", Methods: []string{"GET", "POST"}, FilterFields: []string{"name"}},
	{Group: "WLAN", Name: "WLAN-Broadcast (einzeln)", Path: "sites/*/wifi/broadcasts/*", Methods: []string{"GET", "PUT", "DELETE"}, FilterFields: []string{"name"}},
	// DNS
	{Group: "DNS", Name: "DNS-Policies (Liste / anlegen)", Path: "sites/*/dns/policies", Methods: []string{"GET", "POST"}, FilterFields: []string{"domain"}},
	{Group: "DNS", Name: "DNS-Policy (einzeln)", Path: "sites/*/dns/policies/*", Methods: []string{"GET", "PUT", "DELETE"}, FilterFields: []string{"domain"}},
	// Firewall
	{Group: "Firewall", Name: "Firewall-Zonen (Liste / anlegen)", Path: "sites/*/firewall/zones", Methods: []string{"GET", "POST"}, FilterFields: []string{"name"}},
	{Group: "Firewall", Name: "Firewall-Zone (einzeln)", Path: "sites/*/firewall/zones/*", Methods: []string{"GET", "PUT", "DELETE"}, FilterFields: []string{"name"}},
	{Group: "Firewall", Name: "Firewall-Policies (Liste / anlegen)", Path: "sites/*/firewall/policies", Methods: []string{"GET", "POST"}, FilterFields: []string{"name"}},
	{Group: "Firewall", Name: "Firewall-Policy (einzeln)", Path: "sites/*/firewall/policies/*", Methods: []string{"GET", "PUT", "PATCH", "DELETE"}, FilterFields: []string{"name"}},
	{Group: "Firewall", Name: "Firewall-Policies: Reihenfolge", Path: "sites/*/firewall/policies/ordering", Methods: []string{"GET", "PUT"}},
	// ACL
	{Group: "ACL", Name: "ACL-Regeln (Liste / anlegen)", Path: "sites/*/acl-rules", Methods: []string{"GET", "POST"}, FilterFields: []string{"name"}},
	{Group: "ACL", Name: "ACL-Regel (einzeln)", Path: "sites/*/acl-rules/*", Methods: []string{"GET", "PUT", "DELETE"}, FilterFields: []string{"name"}},
	{Group: "ACL", Name: "ACL-Regeln: Reihenfolge", Path: "sites/*/acl-rules/ordering", Methods: []string{"GET", "PUT"}},
	// Traffic-Listen
	{Group: "Traffic-Listen", Name: "Traffic-Listen (Liste / anlegen)", Path: "sites/*/traffic-matching-lists", Methods: []string{"GET", "POST"}, FilterFields: []string{"name"}},
	{Group: "Traffic-Listen", Name: "Traffic-Liste (einzeln)", Path: "sites/*/traffic-matching-lists/*", Methods: []string{"GET", "PUT", "DELETE"}, FilterFields: []string{"name"}},
	// Hotspot
	{Group: "Hotspot", Name: "Hotspot-Vouchers (Liste / erzeugen / löschen)", Path: "sites/*/hotspot/vouchers", Methods: []string{"GET", "POST", "DELETE"}},
	{Group: "Hotspot", Name: "Hotspot-Voucher (einzeln)", Path: "sites/*/hotspot/vouchers/*", Methods: []string{"GET", "DELETE"}},
	// WAN/VPN/RADIUS
	{Group: "WAN/VPN/RADIUS", Name: "WAN-Schnittstellen (Liste)", Path: "sites/*/wans", Methods: []string{"GET"}},
	{Group: "WAN/VPN/RADIUS", Name: "Site-to-Site-VPN-Tunnel (Liste)", Path: "sites/*/vpn/site-to-site-tunnels", Methods: []string{"GET"}},
	{Group: "WAN/VPN/RADIUS", Name: "VPN-Server (Liste)", Path: "sites/*/vpn/servers", Methods: []string{"GET"}},
	{Group: "WAN/VPN/RADIUS", Name: "RADIUS-Profile (Liste)", Path: "sites/*/radius/profiles", Methods: []string{"GET"}},
}

// EndpointByPath returns the catalog entry for a rule path or false.
func EndpointByPath(path string) (Endpoint, bool) {
	for _, e := range Catalog {
		if e.Path == path {
			return e, true
		}
	}
	return Endpoint{}, false
}
