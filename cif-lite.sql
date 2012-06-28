-- --------------------------------------------
-- SQL Schema for CIF-Lite:
--
-- $ psql -U postgres
-- psql> CREATE DATABASE cif_lite
-- psql> \i cif-lite.sql  
-- --------------------------------------------

-- TABLE to store cif lite data records
DROP TABLE IF EXISTS cif_lite_data CASCADE;
CREATE TABLE cif_lite_data (
	uuid		UUID PRIMARY KEY,			
	value		TEXT NOT NULL,
	first_seen	TIMESTAMP DEFAULT now(),
	last_seen	TIMESTAMP DEFAULT now(),
	source_id	SMALLINT NOT NULL,  		
	impact_id	SMALLINT NOT NULL,  		
	severity_enum	CHAR(1) NOT NULL DEFAULT 'U',  	
	confidence	SMALLINT NOT NULL DEFAULT 0,
	description	TEXT	
);
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
DROP INDEX IF EXISTS value_like_idx CASCADE;
CREATE INDEX value_like_idx ON cif_lite_data (value text_pattern_ops);

-- TABLE storing the impact lookup
DROP SEQUENCE IF EXISTS impact_id_seq CASCADE;
CREATE SEQUENCE impact_id_seq;
DROP TABLE IF EXISTS cif_impact_lookup CASCADE;
CREATE TABLE cif_impact_lookup (
	id	SMALLINT NOT NULL PRIMARY KEY DEFAULT nextval('impact_id_seq'),
	impact	TEXT NOT NULL UNIQUE
);
ALTER SEQUENCE impact_id_seq OWNED BY cif_impact_lookup.id;

-- TABLE storing the source lookup
DROP SEQUENCE IF EXISTS source_id_seq CASCADE;
CREATE SEQUENCE source_id_seq;
DROP TABLE IF EXISTS cif_source_lookup CASCADE;
CREATE TABLE cif_source_lookup (
	id 	SMALLINT NOT NULL PRIMARY KEY DEFAULT nextval('source_id_seq'),
	source	TEXT NOT NULL UNIQUE
);
ALTER SEQUENCE source_id_seq OWNED BY cif_source_lookup.id;

-- TABLE storing recent additions for creation of daily datafeeds
DROP TABLE IF EXISTS cif_recent_additions CASCADE;
CREATE TABLE cif_recent_additions (
	data_uuid	UUID PRIMARY KEY,
	add_timestamp	TIMESTAMP DEFAULT now()
);

