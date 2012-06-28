package CIF::Lite;

########################################################
# Module to override original CIF IODEF Archive Storage
# into my own customer "CIF LITE" schema.
#  - Mike Geide (mgeide on gmail)
########################################################

use strict;
use warnings;
use DateTime;
use OSSP::uuid;
use Class::DBI;
#use Data::Dumper; # For debugging

##########################################
# Insert CIF records into CIF-Lite format
##########################################
sub insert_records {
  my $config = shift;	
  my $recs   = shift;

  ##Previously hard-coded DB connection for testing
  ##my $dbh = DBI->connect("dbi:Pg:dbname=cif_lite","postgres","", { PrintError => 0 } ) 
 
  my $db_config = $config->{'database'};
  my $dbh = DBI->connect($db_config->[0], $db_config->[1], $db_config->[2], $db_config->[3] ) 
   	    or die "Cannot connect: $DBI::errstr\n";
  
  my $impact_href = _get_impacts($dbh);
  my $source_href = _get_sources($dbh);

  ## CIF Lite data SQL statement handles  
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
    	                or die "[ERROR] preparing cif data Insert statement: $dbh->errstr\n";
  my $update_data_sth = $dbh->prepare("UPDATE cif_lite_data SET last_seen=?, severity_enum=?, confidence=?, description=? WHERE uuid=?")
    	                or die "[ERROR] preparing cif data Update statement: $dbh->errstr\n";
  my $insert_recent_sth = $dbh->prepare("INSERT INTO cif_recent_additions (data_uuid, add_timestamp) VALUES (?,?)")
                          or die "[ERROR] preparing cif recent addition Insert statement: $dbh->errstr\n";  
  
  my $dt = DateTime->now();
  my $current_timestamp = $dt->datetime();

  ## Loop through records inserting / updating as appropriate
  foreach my $rec ( @$recs ) {

    ## Normalize the record into a hash based on the CIF Lite schema
    my $rec_href = _normalize_record( $dbh, $impact_href, $source_href, $rec );

    unless ( $rec_href < 0 ) {

      ## INSERT cif-lite data
      my $insert_response = $insert_data_sth->execute( $rec_href->{'uuid'},
        					       $rec_href->{'value'},
        		   		  	       $rec_href->{'first_seen'},
        					       $rec_href->{'last_seen'},
        		  			       $rec_href->{'source_id'},
        					       $rec_href->{'impact_id'},
        					       $rec_href->{'severity_enum'},
        					       $rec_href->{'confidence'},
        					       $rec_href->{'description'} );
                            #or die "[ERROR] executing CIF Lite data insert statement: " . $dbh->errstr . "\n";
   		
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
        # Insert succeeded, add this is a recent addition
        my $recent_insert_retval = $insert_recent_sth->execute( $rec_href->{'uuid'},
                                                                $current_timestamp )
                                   or die "[ERROR] executing CIF Lite recent insert statement: $dbh->errstr\n";
        if (!$recent_insert_retval) {
            print "[DEBUG, ERROR] trying to insert recent data record: $dbh->errstr\n";
        }
        else {
          print "[DEBUG] INSERTED " . $rec_href->{'uuid'} . " -- " . $rec_href->{'value'} . ".\n";
        }
      }
 		
    }
    else {
      print "[DEBUG, ERROR] Record normalization failed with code $rec_href\n";
    }
  }
  
  $insert_data_sth->finish;
  $update_data_sth->finish; 
  $dbh->disconnect();
}

###########################
# Get impact lookup values
###########################
sub _get_impacts {
  my $dbh = shift;

  my %impacts;
  my $select_impact_sth = $dbh->prepare("SELECT * FROM cif_impact_lookup")
                          or die "[ERROR] preparing Impact select statement: $dbh->errstr\n";
  my $retval = $select_impact_sth->execute or die "[ERROR] executing Impact select statement: $dbh->errstr\n";
  if (!$retval) {
    $select_impact_sth->finish;
    return -1;
  } else {
    while ( my $href = $select_impact_sth->fetchrow_hashref() ) {
      $impacts{ $href->{'impact'} } = $href->{'id'};
      print "[DEBUG] Loading impact " . $href->{'impact'} . ".\n";
    }
    $select_impact_sth->finish;
  }
  return \%impacts;  
}

##########################
# Add impact lookup value
##########################
sub _add_impact {
  my $dbh    = shift;
  my $impact = shift;

  my $insert_impact_sth = $dbh->prepare("INSERT INTO cif_impact_lookup (impact) VALUES (?) RETURNING id")
                          or die "[ERROR] preparing Impact insert statement: $dbh->errstr\n";

  my $retval = $insert_impact_sth->execute($impact); #or die "[ERROR] executing Impact insert statement for $impact: " . $dbh->errstr . "\n";
  if (!$retval) {
    $insert_impact_sth->finish;
    my $impacts_href = _get_impacts($dbh);
    if (exists $impacts_href->{$impact}) {
      return $impacts_href->{$impact};
    } 
    return -1;
  } else {
    my $rowval = $insert_impact_sth->fetchrow_hashref();
    $insert_impact_sth->finish;
    print "[DEBUG] Adding impact " . $impact . " (" . $rowval->{'id'} . ").\n"; 
    return $rowval->{'id'};
  }
}

###########################
# Get source lookup values
###########################
sub _get_sources {
  my $dbh = shift;

  my %sources;
  my $select_source_sth = $dbh->prepare("SELECT * FROM cif_source_lookup")
                          or die "[ERROR] preparing Source select statement: $dbh->errstr\n";
  my $retval = $select_source_sth->execute or die "[ERROR] executing Source select statement: $dbh->errstr\n";
  if (!$retval) {
    $select_source_sth->finish;
    return -1;
  } else {
    while ( my $href = $select_source_sth->fetchrow_hashref() ) {
      $sources{ $href->{'source'} } = $href->{'id'};
      print "[DEBUG] Loading source " . $href->{'source'} . ".\n";
    }
    $select_source_sth->finish;
  }
  return \%sources;  
}

##########################
# Add source lookup value
##########################
sub _add_source {
  my $dbh    = shift;
  my $source = shift;

  my $insert_source_sth = $dbh->prepare("INSERT INTO cif_source_lookup (source) VALUES (?) RETURNING id")
                          or die "[ERROR] preparing Source insert statement: $dbh->errstr\n";

  my $retval = $insert_source_sth->execute($source); #or die "[ERROR] executing Source insert statement for $source: " . $dbh->errstr . "\n";
  if (!$retval) {
    $insert_source_sth->finish;
    my $sources_href = _get_sources($dbh);
    if (exists $sources_href->{$source}) {
      return $sources_href->{$source};
    }
    return -1;
  } else {
    my $rowval = $insert_source_sth->fetchrow_hashref();
    $insert_source_sth->finish;
    print "[DEBUG] Adding source " . $source . " (" . $rowval->{'id'} . ").\n";
    return $rowval->{'id'}; 
  }
}



####################
# Normalize Record
####################
sub _normalize_record {
  my $dbh         = shift;
  my $impact_href = shift;
  my $source_href = shift;
  my $rec         = shift;

  my %severity_enum = (
           'high'   => 'H',
           'medium' => 'M',
           'low'    => 'L',
           'undef'  => 'U',
     );
  
  my %nrec; ## normalized record

  ## Do we know the source, get Id
  if (exists $rec->{'source'}) {
    if (exists $source_href->{ $rec->{'source'} }) {
      $nrec{'source_id'} = $source_href->{ $rec->{'source'} };
    }
    else {
      my $source_id = _add_source($dbh, $rec->{'source'});
      if ($source_id > -1) {
        $nrec{'source_id'} = $source_id;
      } else {
        print "[DEBUG, ERROR] unable to add source " . $rec->{'source'} . ".\n"; 
        return -1; 
      }
    }
  } else {
    print "[DEBUG, ERROR] source field does not exist in CIF record.\n"; 
    return -2; 
  }

  ## Do we know the impact, get Id
  if (exists $rec->{'impact'}) {
    if (exists $impact_href->{ $rec->{'impact'} }) {
      $nrec{'impact_id'} = $impact_href->{ $rec->{'impact'} };
    }
    else {
      my $impact_id = _add_impact($dbh, $rec->{'impact'});
      if ($impact_id > -1) {
        $nrec{'impact_id'} = $impact_id;
      } else {
        print "[DEBUG, ERROR] unable to add impact " . $rec->{'impact'} . "\n";  
        return -3; 
      }
    }
  } else {
    print "[DEBUG, ERROR] impact field does not exist in CIF record.\n"; 
    return -4; 
  }  

  ## Record value (address, md5, malware_md5, malware_sha1, etc.)
  if (exists $rec->{'address'}) {
    $nrec{'value'} = $rec->{'address'};
  } elsif (exists $rec->{'md5'}) {
    $nrec{'value'} = $rec->{'md5'};
  } elsif (exists $rec->{'malware_md5'}) {
    $nrec{'value'} = $rec->{'malware_md5'};
  } elsif (exists $rec->{'malware_sha1'}) {
    $nrec{'value'} = $rec->{'malware_sha1'};
  } else { 
    print "[DEBUG, ERROR] a value field does not exist in CIF record.\n";
    return -5; 
  }

  ## UUID based on (value,source,impact)
  my $uuid_str = _build_uuid($nrec{'value'},
                             $nrec{'source_id'},
                             $nrec{'impact_id'});
  if ($uuid_str =~ /[0-9a-f\-]+/i) {
    $nrec{'uuid'} = $uuid_str;
  }  else {
    print "[DEBUG, ERROR] UUID incorrectly created: $uuid_str.\n"; 
    return -6; 
  }  

  ## First Seen / Last Seen
  if (exists $rec->{'detecttime'}) {
    $nrec{'first_seen'} = $rec->{'detecttime'};
    $nrec{'last_seen'} = $rec->{'detecttime'};
  } else { 
    my $dt = DateTime->now();
    $nrec{'first_seen'} = $dt->datetime();
    $nrec{'last_seen'} = $dt->datetime();
  }

  ## Severity
  if (exists $rec->{'severity'}) {
    if (exists $severity_enum{ $rec->{'severity'} }) {
      $nrec{'severity_enum'} = $severity_enum{ $rec->{'severity'} };
    } else { 
      $nrec{'severity_enum'} = $severity_enum{'undef'}; 
    }
  } else {
    $nrec{'severity_enum'} = $severity_enum{'undef'};
  }

  ## Confidence
  if (exists $rec->{'confidence'}) {		
    $nrec{'confidence'} = $rec->{'confidence'};
    if ($nrec{'confidence'} > 100) { $nrec{'confidence'} = 100; }
    elsif ($nrec{'confidence'} < 0) { $nrec{'confidence'} = 0; }
  } else { $nrec{'confidence'} = 0; }

  ## Description
  if (exists $rec->{'description'}) {				
    $nrec{'description'} = $rec->{'description'};
  } else { $nrec{'description'} = ""; }
	
  return \%nrec;
}

##############
# Build_UUID
##############
sub _build_uuid {
  my $value  = shift;
  my $source = shift;
  my $impact = shift;
  my $uuid_seed = $value . $source . $impact;

  my $uuid = OSSP::uuid->new();
  my $uuid_ns = OSSP::uuid->new();
  $uuid_ns->load('ns::URL');
  $uuid->make("v3",$uuid_ns,$uuid_seed);
  my $uuid_str = $uuid->export('str');
  undef $uuid;
  return($uuid_str);
} 



1;
