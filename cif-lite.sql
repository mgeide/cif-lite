-- --------------------------------------------
-- SQL Schema for CIF-Lite:
--
-- $ psql -U postgres
-- psql> CREATE DATABASE cif_lite
-- psql> \i cif-lite.sql  
-- --------------------------------------------

-- --------------------------------------------------------- --
-- CIF Lite Data                                             --
--  (old, decided against jamming everything into one table) --
-- --------------------------------------------------------- --
-- TABLE to store cif lite data records
-- DROP TABLE IF EXISTS cif_lite_data CASCADE;
-- CREATE TABLE cif_lite_data (
--	uuid		UUID PRIMARY KEY,			
--	value		TEXT NOT NULL,
--	first_seen	TIMESTAMP DEFAULT now(),
--	last_seen	TIMESTAMP DEFAULT now(),
--	source_id	SMALLINT NOT NULL,  		
--	impact_id	SMALLINT NOT NULL,  		
--	severity_enum	CHAR(1) NOT NULL DEFAULT 'U',  	
--	confidence	SMALLINT NOT NULL DEFAULT 0,
--	description	TEXT	
-- );
-- cif_lite_data NOTE:
-- uuid: UUID uniquely defining value,source,impact triad
-- source_id: references cif_source_lookup.id (enforce in code, not DB constraint)
-- impact_id: references cif_impact_lookup.id (enforce in code, not DB constraint)
-- severity_enum: H: high, M: medium, L: low, U: undefined (set/define these in code vs DB enum)
-- UUID created from value,source,impact triad used for unique inserts and exists updates
-- Below index is assumed because UUID is primary key, add this if we go back to a separate SERIAL id:
-- CREATE UNIQUE INDEX uuid_idx ON cif_lite_data(uuid);
-- cif_lite_data additional INDEX:
-- VALUE index for queries to include the use of regex / LIKE:
-- DROP INDEX IF EXISTS value_like_idx CASCADE;
-- CREATE INDEX value_like_idx ON cif_lite_data (value text_pattern_ops);

-- ----------- --
-- CIF Lite IP --
-- ----------- --
DROP TABLE IF EXISTS cif_lite_ip CASCADE;
CREATE TABLE cif_lite_ip (
	uuid		    UUID PRIMARY KEY,			
	value		    INET NOT NULL,   -- Note the INET data-type
	first_seen	    TIMESTAMP DEFAULT now(),
	last_seen	    TIMESTAMP DEFAULT now(),
	source_id	    SMALLINT NOT NULL,  		
	impact_id	    SMALLINT NOT NULL,  		
	severity_enum	    CHAR(1) NOT NULL DEFAULT 'U',  	
	confidence	    SMALLINT NOT NULL DEFAULT 0,
	description	    TEXT	
);
DROP INDEX IF EXISTS ip_value_idx CASCADE;
CREATE INDEX ip_value_idx ON cif_lite_ip (value);

-- --------------- --
-- CIF Lite Domain --
-- --------------- --
DROP TABLE IF EXISTS cif_lite_domain CASCADE;
CREATE TABLE cif_lite_domain (
	uuid		    UUID PRIMARY KEY,			
	value		    TEXT NOT NULL,
	first_seen	    TIMESTAMP DEFAULT now(),
	last_seen	    TIMESTAMP DEFAULT now(),
	source_id	    SMALLINT NOT NULL,  		
	impact_id	    SMALLINT NOT NULL,  		
	severity_enum	    CHAR(1) NOT NULL DEFAULT 'U',  	
	confidence	    SMALLINT NOT NULL DEFAULT 0,
	description 	    TEXT	
);
DROP INDEX IF EXISTS domain_value_idx CASCADE;
CREATE INDEX domain_value_idx ON cif_lite_domain (value text_pattern_ops);

-- ------------ --
-- CIF Lite URL --
-- ------------ --
DROP TABLE IF EXISTS cif_lite_url CASCADE;
CREATE TABLE cif_lite_url (
	uuid		    UUID PRIMARY KEY,			
	value		    TEXT NOT NULL,
	first_seen	    TIMESTAMP DEFAULT now(),
	last_seen	    TIMESTAMP DEFAULT now(),
	source_id	    SMALLINT NOT NULL,  		
	impact_id	    SMALLINT NOT NULL,  		
	severity_enum	    CHAR(1) NOT NULL DEFAULT 'U',  	
	confidence	    SMALLINT NOT NULL DEFAULT 0,
	description 	    TEXT	
);
DROP INDEX IF EXISTS url_value_idx CASCADE;
CREATE INDEX url_value_idx ON cif_lite_url (value text_pattern_ops);

-- -------------- --
-- CIF Lite Email --
-- -------------- --
DROP TABLE IF EXISTS cif_lite_email CASCADE;
CREATE TABLE cif_lite_email (
	uuid		    UUID PRIMARY KEY,			
	value		    TEXT NOT NULL,
	first_seen	    TIMESTAMP DEFAULT now(),
	last_seen	    TIMESTAMP DEFAULT now(),
	source_id	    SMALLINT NOT NULL,  		
	impact_id	    SMALLINT NOT NULL,  		
	severity_enum	    CHAR(1) NOT NULL DEFAULT 'U',  	
	confidence	    SMALLINT NOT NULL DEFAULT 0,
	description 	    TEXT	
);
DROP INDEX IF EXISTS email_value_idx CASCADE;
CREATE INDEX email_value_idx ON cif_lite_email (value text_pattern_ops);

-- ------------ --
-- CIF Lite MD5 --
-- ------------ --
DROP TABLE IF EXISTS cif_lite_md5 CASCADE;
CREATE TABLE cif_lite_md5 (
	uuid		    UUID PRIMARY KEY,			
	value		    TEXT NOT NULL,
	first_seen	    TIMESTAMP DEFAULT now(),
	last_seen	    TIMESTAMP DEFAULT now(),
	source_id	    SMALLINT NOT NULL,  		
	impact_id	    SMALLINT NOT NULL,  		
	severity_enum	    CHAR(1) NOT NULL DEFAULT 'U',  	
	confidence	    SMALLINT NOT NULL DEFAULT 0,
	description	    TEXT	
);
DROP INDEX IF EXISTS md5_value_idx CASCADE;
CREATE INDEX md5_value_idx ON cif_lite_md5 (value);

-- ------------- --
-- CIF Lite SHA1 --
-- ------------- --
DROP TABLE IF EXISTS cif_lite_sha1 CASCADE;
CREATE TABLE cif_lite_sha1 (
	uuid		    UUID PRIMARY KEY,			
	value		    TEXT NOT NULL,
	first_seen	    TIMESTAMP DEFAULT now(),
	last_seen	    TIMESTAMP DEFAULT now(),
	source_id	    SMALLINT NOT NULL,  		
	impact_id	    SMALLINT NOT NULL,  		
	severity_enum	    CHAR(1) NOT NULL DEFAULT 'U',  	
	confidence	    SMALLINT NOT NULL DEFAULT 0,
	description	    TEXT	
);
DROP INDEX IF EXISTS sha1_value_idx CASCADE;
CREATE INDEX sha1_value_idx ON cif_lite_sha1 (value);

-- ------------- --
-- Impact lookup --
-- ------------- --
DROP TABLE IF EXISTS cif_impact_lookup CASCADE;
CREATE TABLE cif_impact_lookup (
	id	SMALLINT NOT NULL PRIMARY KEY,
	impact	TEXT NOT NULL UNIQUE
);

-- ------------- --
-- Source lookup --
-- ------------- --
DROP TABLE IF EXISTS cif_source_lookup CASCADE;
CREATE TABLE cif_source_lookup (
	id 	SMALLINT NOT NULL PRIMARY KEY,
	source	TEXT NOT NULL UNIQUE
);

-- ---------- --
-- Recent IPs --
-- ---------- --
DROP TABLE IF EXISTS cif_recent_ip CASCADE;
CREATE TABLE cif_recent_ip (
	data_uuid	UUID PRIMARY KEY,
	add_timestamp	TIMESTAMP DEFAULT now()
);

-- -------------- --
-- Recent Domains --
-- -------------- --
DROP TABLE IF EXISTS cif_recent_domain CASCADE;
CREATE TABLE cif_recent_domain (
	data_uuid	UUID PRIMARY KEY,
	add_timestamp	TIMESTAMP DEFAULT now()
);

-- ----------- --
-- Recent URLs --
-- ----------- --
DROP TABLE IF EXISTS cif_recent_url CASCADE;
CREATE TABLE cif_recent_url (
	data_uuid	UUID PRIMARY KEY,
	add_timestamp	TIMESTAMP DEFAULT now()
);

-- ------------- --
-- Recent Emails --
-- ------------- --
DROP TABLE IF EXISTS cif_recent_email CASCADE;
CREATE TABLE cif_recent_email (
	data_uuid	UUID PRIMARY KEY,
	add_timestamp	TIMESTAMP DEFAULT now()
);

-- ----------- --
-- Recent MD5s --
-- ----------- --
DROP TABLE IF EXISTS cif_recent_md5 CASCADE;
CREATE TABLE cif_recent_md5 (
	data_uuid	UUID PRIMARY KEY,
	add_timestamp	TIMESTAMP DEFAULT now()
);

-- ------------ --
-- Recent SHA1s --
-- ------------ --
DROP TABLE IF EXISTS cif_recent_sha1 CASCADE;
CREATE TABLE cif_recent_sha1 (
	data_uuid	UUID PRIMARY KEY,
	add_timestamp	TIMESTAMP DEFAULT now()
);

-- --------- --
-- Relations --
-- --------- --
DROP TABLE IF EXISTS cif_relations CASCADE;
CREATE TABLE cif_relations (
	id	                SERIAL PRIMARY KEY,
	relation_uuid	        UUID NOT NULL,
	entity_type		CHAR(1) NOT NULL, -- Enum: I=IP, U=URL, D=Domain, M=MD5, S=SHA1, E=Email
	entity_uuid		UUID NOT NULL
);

