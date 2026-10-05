-- This bootstrap runs before policy tables and all other generated objects.
CREATE FUNCTION @extschema@.password_profile_require_preload()
RETURNS void
AS 'MODULE_PATHNAME', 'password_profile_require_preload_wrapper'
LANGUAGE c;

REVOKE ALL ON FUNCTION @extschema@.password_profile_require_preload() FROM PUBLIC;
SELECT @extschema@.password_profile_require_preload();
