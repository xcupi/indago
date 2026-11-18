-- Explicit opt-out to the legacy host-only (any scheme, any port) behaviour.
--
-- This flag does not widen the matcher: a non-empty allowed_origins list always
-- wins. It exists so an operator can record a knowing choice of "any scheme and
-- port" on a scope saved after origin rules existed, instead of the other
-- empty-list shape (0 with no origins), which is reserved for scopes saved
-- before the feature. Write surfaces never create that legacy shape; existing
-- rows read back 0, which preserves their behaviour exactly.
ALTER TABLE scopes ADD COLUMN allow_any_scheme_ports INTEGER NOT NULL DEFAULT 0;
