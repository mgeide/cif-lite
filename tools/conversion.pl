#!/usr/bin/perl

#########
#
# convert CIF archive table into CIF-Lite database
#
# Ultimately abandoned this project, because the CIF databse was so big 
# to process.  Either need to use database cursor or pg_dump and then process file.
# It is much easier to start all over again and build up the new DB.
#
#########


use strict;
use warnings;

# fix lib paths, some may be relative
BEGIN {
    require File::Spec;
    my @libs = ("lib", "local/lib");
    my $bin_path;

    for my $lib (@libs) {
        unless ( File::Spec->file_name_is_absolute($lib) ) {
            unless ($bin_path) {
                if ( File::Spec->file_name_is_absolute(__FILE__) ) {
                    $bin_path = ( File::Spec->splitpath(__FILE__) )[1];
                }
                else {
                    require FindBin;
                    no warnings "once";
                    $bin_path = $FindBin::Bin;
                }
            }
            $lib = File::Spec->catfile( $bin_path, File::Spec->updir, $lib );
        }
        unshift @INC, $lib;
    }

}

use Class::DBI;
use CIF::Lite;

# Open CIF database
my $cif_dbname = "cif";
my $cif_uname  = "postgres";
my $cif_pass   = "";
my $cif_dbh = DBI->connect("dbi:Pg:dbname=$cif_dbname", "$cif_uname", "$cif_pass") 
   	    or die "Cannot connect: $DBI::errstr\n";
# And CIF-Lite database
my $ciflite_dbname = "cif_lite";
my $ciflite_uname  = "postgres";
my $ciflite_pass   = "";
my $ciflite_dbh = DBI->connect("dbi:Pg:dbname=$ciflite_dbname", "$ciflite_uname", "$ciflite_pass") 
   	    or die "Cannot connect: $DBI::errstr\n";

# Select from Archive table in CIF  	    
my $select_query = "SELECT * FROM archive";
my $sth = $cif_dbh->prepare($select_query) or die "Error preparing select: $DBI::errstr\n";
my $ret = $sth->execute();
if (!$rv) {
	die "Error executing select: " . $cif_dbh->errstr . "\n";
} 
else {
	# Prepare CIF-Lite Insertions
	my $impact_href = CIF::Lite::_get_impacts($ciflite_dbh);
	my $source_href = CIF::Lite::_get_sources($ciflite_dbh);
	my $source_uuid_href = source_uuids(); 
	
	my $insert_data_sth = $dbh->prepare("INSERT INTO cif_lite_data (uuid, 
                                                                  value, 
                                                                  first_seen,
                                                                  last_seen,
                                                                  source_id,
                                                                  impact_id,
                                                                  severity_enum,
                                                                  confidence,
                                                                  description) 
                                       VALUES (?,?,?,?,?,?,?,?,?)")
                        or die "[ERROR] preparing cif-lite data Insert statement: $ciflite_dbh->errstr\n";
    my $update_data_sth = $dbh->prepare("UPDATE cif_lite_data SET last_seen=?, severity_enum=?, confidence=?, description=? WHERE uuid=?")
                        or die "[ERROR] preparing cif-lite data Update statement: $ciflite_dbh->errstr\n";
	
	my $dt = DateTime->now();
    my $current_timestamp = $dt->datetime();
	
	# Loop thru Archive records
	while ( my $href = $sth->fetchrow_hashref() ) {
		my %new_record;
		
		my $source_uuid = $href->{'source'};  ## convert UUID to string
		if (exists $source_uuid_href->{$source_uuid}) {
			$new_record{'source'} = $source_uuid_href->{$source_uuid};
		}
		$new_record{'description'} = $href->{'description'};
		$new_record{'detecttime'}  = $href->{'created'};
		my $json_data   = $href->{'data'};
		
		if ($json_data =~ /Impact\"\:\{\"content\"\:\"(.*?)\"\,\"severity\"\:\"(.*?)\"(.*)/) {
			$new_record{'impact'}   = $1;  
			$new_record{'severity'} = $2;  
			$json_data = $3;	
		}
		if ($json_data =~ /Confidence\"\:\{\"content\"\:\"(\d+)\"(.*)/) {
			$new_record{'confidence'} = $1;
			$json_data = $2;
		}
		if ($json_data =~ /Address\"\:\"content\"\:\"(.*?)\"(.*)/) {
			$new_record{'address'} = $1;
			$json_data = $2;
		}
		
		## Insert based on above info
		my $rec_href = CIF::Lite::_normalize_record( $dbh, $impact_href, $source_href, \%new_record );
		unless ( $rec_href < 0 )  {}
		  insert_record( \%new_record, $insert_data_sth, $update_data_sth )
	 	}
		
		## TODO: additional, linked data
		while ($json_data =~ /AdditionalData\"\:\{(.*?)\}(.*)/) {
			my $additional_data = $1;
			$json_data = $2;
			if ($additional_data =~ /content\"\:\"(.*?)\"\,\"meaning\"\:\"(.*?)\"/) {
				my $data    = $1;
				my $meaning = $2;
				if ($meaning =~ /(md5|sha1|malware_md5|malware_sha1|address)/) {
					$rec_href->{'value'} = $data;
					insert_record( \%new_record, $insert_data_sth, $update_data_sth );
				}
			}
		}
	}
}

$cif_dbh->disconnect();
$ciflite_dbh->disconnect();

sub source_uuids {
  my %uuids;
  my @sources = `grep -h "^source = .*" /opt/cif/etc/*.cfg`;
  foreach my $source (@sources) {
    chomp $source;
    $source =~ s/^source = //;
    $uuid = uuid_calc($source);
 
    unless (exists $uuids{$uuid}) {
      $uuids{$uuid} = $source;
    }
  }
}

sub uuid_calc {
  my $source = shift;
  my $uuid = OSSP::uuid->new();
  my $uuid_ns = OSSP::uuid->new();
  $uuid_ns->load('ns::URL');
  $uuid->make("v3",$uuid_ns,$source);
  my $str = $uuid->export('str');
  undef $uuid;
  return($str);
}

sub insert_record {
	my $rec_href = shift;
	my $insert_data_sth = shift;
	my $update_data_sth = shift;	
	
	  my $insert_response = $insert_data_sth->execute( $rec_href->{'uuid'},
                                                       $rec_href->{'value'},
                                                       $rec_href->{'first_seen'},
                                                       $rec_href->{'last_seen'},
                                                       $rec_href->{'source_id'},
                                                       $rec_href->{'impact_id'},
                                                       $rec_href->{'severity_enum'},
                                                       $rec_href->{'confidence'},
                                                       $rec_href->{'description'} );

      if (!$insert_response) {

        my $update_response = $update_data_sth->execute( $rec_href->{'last_seen'},
                                                         $rec_href->{'severity_enum'},
                                                         $rec_href->{'confidence'},
                                                         $rec_href->{'description'},
                                                         $rec_href->{'uuid'} )
                              or die "[ERROR] executing CIF Lite update statement: $dbh->errstr\n";

          if (!$update_response) {
            print "[DEBUG, ERROR] trying to insert/update data record: $dbh->errstr\n";
          }
          else {
            print "[DEBUG] UPDATED " . $rec_href->{'uuid'} . " -- " . $rec_href->{'value'} . ".\n";
          }
      }
      else {
      	print "[DEBUG] INSERTED " . $rec_href->{'uuid'} . " -- " . $rec_href->{'value'} . ".\n";
      }
	
}
