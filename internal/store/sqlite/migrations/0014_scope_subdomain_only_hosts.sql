-- Wildcard (subdomains-only) scope entries.
--
-- A bug-bounty program that scopes "*.example.com" does not scope the apex
-- ("example.com"), and an exact-host asset ("www.example.com") does not scope
-- its subdomains. IncludeHosts cannot express either shape: a leading dot with
-- allow_subdomains always includes the base host too. The importer therefore
-- records wildcard assets here, and Scope.Permits requires a strict subdomain
-- for them (never the host itself).
ALTER TABLE scopes ADD COLUMN subdomain_only_hosts TEXT NOT NULL DEFAULT '[]';
