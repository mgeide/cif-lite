#!/usr/bin/perl

use strict;

use lib '/opt/cif/lib';
use Class::DBI;
use CIF::Lite;

my $config_file = $ARGV[0];
my %configs;
my $latest_conf = '';
open(CONF, $config_file) or die "[ERROR] opening $config_file\n";
while (my $line = <CONF>) {
  chomp($line);
  if ($line =~ /^#/) { next; }
  elsif ($line =~ /^\[(.*?)\]$/) {
    my $conf_name = $1;
    $configs{$conf_name} = ();
    $latest_conf = $conf_name;
  }
  elsif ($line =~ /^file: (.*)/) {
    my $file_path = $1;
    my $conf_href = $configs{$latest_conf};
    $conf_href->{'file'} = $file_path;  
  }
  ## TODO: continue along this path to receive and generate blocklist specs
} 
close(CONF);

# Connect to the CIF-Lite database
# TODO: don't hard-code this
my $ciflite_dbname = "cif_lite";
my $ciflite_uname  = "postgres";
my $ciflite_pass   = "";
my $ciflite_dbh = DBI->connect("dbi:Pg:dbname=$ciflite_dbname", "$ciflite_uname", "$ciflite_pass") 
            or die "Cannot connect: $DBI::errstr\n";


# Filter settings
# TODO: don't hard-code this
my $severity_filter = 'H';
my $confidence_min = 65;


my %severity_score = (
	'L' => 1,
	'M' => 2,
	'H' => 3,
);

# Get the sources and impacts
my $sql_href = CIF::Lite::_sql_statements($ciflite_dbh);
my $impacts_href = CIF::Lite::_get_impacts($ciflite_dbh, $sql_href);
my %impact_ids = reverse %$impacts_href;
my $sources_href = CIF::Lite::_get_sources($ciflite_dbh, $sql_href);
my %source_ids = reverse %$sources_href;

## Loop thru types
my @types = ( 'ip', 'domain', 'url', 'md5', 'sha1' );
foreach my $type (@types) {

	## Get recent records for the type
	my $results_aref = _get_recents($ciflite_dbh, $type);

	## Loop thru the recent records
	foreach my $result_aref (@$results_aref) {

		my $value      = $result_aref->[0];
		my $severity   = $result_aref->[1];
		my $confidence = $result_aref->[2];
		my $source_id  = $result_aref->[3];	
		my $impact_id  = $result_aref->[4];

		my $source = $source_ids{$source_id};
		my $impact = $impact_ids{$impact_id};
		
		## Apply filters -- TODO: improve how the filtering is done, e.g., conf file
		if ($confidence < $confidence_min) { next; }
		if ($severity_score{$severity} < $severity_score{$severity_filter}) { next; }		

		## TODO: figure out whitelisting
		print "$value | $severity | $confidence | $impact | $source\n";
	}
	
	last;
}


############################
# Get the recent additions #
############################
sub _get_recents {
	my $dbh      = shift;
	my $type     = shift;

	my @records;

	my $sql = "SELECT cif_lite_$type.value,cif_lite_$type.severity_enum,cif_lite_$type.confidence,cif_lite_$type.source_id,cif_lite_$type.impact_id FROM cif_recent_$type,cif_lite_$type WHERE cif_recent_$type.data_uuid=cif_lite_$type.uuid";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $records_aref = $sth->fetchall_arrayref();
	$sth->finish;

	return $records_aref; 
}

