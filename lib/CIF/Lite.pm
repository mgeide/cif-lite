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
use Data::Dumper; # For debugging

#################################
# GLOBALs / Configuration
#  - Update these as appropriate
#################################

my %_RECTYPE_ENUM = ( 'ip'     => 'I',
		      'domain' => 'D',
	       	      'url'    => 'U',
		      'email'  => 'E',
		      'md5'    => 'M',
		      'sha1'   => 'S',
		    );

my %_SEVERITY_ENUM = ( 'high'   => 'H',
                       'medium' => 'M',
                       'low'    => 'L',
                       'undef'  => 'U',
                     );

my $_MIN_VALUE_LENGTH = 4;                     
  

##########################################
# Insert CIF records into CIF-Lite format
##########################################
sub insert_records {
  my $config = shift;	
  my $recs   = shift;

  # Connect to the DB based on what's in the config 
  my $db_config = $config->{'database'};
  my $dbh = DBI->connect($db_config->[0], $db_config->[1], $db_config->[2], $db_config->[3] ) 
   	        or die "Cannot connect: $DBI::errstr\n";

  # Build the SQL statements, and get the impact/source lookups
  my $sth_href    = _sql_statements($dbh);  
  my $impact_href = _get_impacts($dbh, $sth_href);
  my $source_href = _get_sources($dbh, $sth_href);
  
  my $dt = DateTime->now();
  my $current_timestamp = $dt->datetime();

  ## Loop through records inserting / updating as appropriate
  foreach my $rec ( @$recs ) {

    ## Normalize the record into an array of CIF Lite hash records
    my $recs_aref = _normalize_records( $dbh, $sth_href, $impact_href, $source_href, $rec );

    ## Store records
    my $relation_flag = 0;
    foreach my $rec_href (@$recs_aref) {
      my $ret_val = _store_record( $dbh, $sth_href, $rec_href );
      ## Set the relation flag on INSERTs (a ret_val of 2)
      if ($ret_val == 2) {
      	$relation_flag = 1;  
      }
    }
    
    ## Store relationships
    if (($relation_flag) and (scalar (@$recs_aref) > 1)) {
    	_store_relations( $dbh, $sth_href, $recs_aref );
    }

  }
  
  # DB Clean-up 
  _db_cleanup($dbh, $sth_href);
}

#################
# DB Cleanup
#################
sub _db_cleanup {
	my $dbh = shift;
	my $sth_href = shift;
	
	foreach my $sth_key (keys %$sth_href) {
		($sth_href->{$sth_key})->finish;
	}
	$dbh->disconnect();
}

########################
# SQL Statement Handles
########################
sub _sql_statements {
  my $dbh = shift;
  
  my %sths;
  
  # Select impact id
  $sths{"select impact id"} = $dbh->prepare("SELECT MAX(id) FROM cif_impact_lookup")
                              or die "[ERROR] Preparing Impact Id Select statement: " . $dbh->errstr . "\n";
  # Select impacts
  $sths{"select impacts"} = $dbh->prepare("SELECT * FROM cif_impact_lookup")
  							or die "[ERROR] Preparing Impact Select Statement: " . $dbh->errstr . "\n";
  # Insert impacts
  $sths{"insert impacts"} = $dbh->prepare("INSERT INTO cif_impact_lookup (id, impact) VALUES (?, ?)")
                          	or die "[ERROR] Preparing Impact insert statement: " . $dbh->errstr . "\n";
  # Select source id
  $sths{"select source id"} = $dbh->prepare("SELECT MAX(id) FROM cif_source_lookup")
			      or die "[ERROR] Preparing Source Id Select statement: " . $dbh->errstr . "\n";  

  # Select sources
  $sths{"select sources"} = $dbh->prepare("SELECT * FROM cif_source_lookup")
                          	or die "[ERROR] Preparing Source select statement: " . $dbh->errstr . "\n";
  # Insert sources
  $sths{"insert sources"} = $dbh->prepare("INSERT INTO cif_source_lookup (id, source) VALUES (?, ?)")
                          	or die "[ERROR] Preparing Source insert statement: " . $dbh->errstr . "\n";
 
  
  my @data_types = ('url', 'domain', 'ip', 'email', 'md5', 'sha1'); 
  foreach my $data_type (@data_types) {
    
    # Insert CIF data
  	$sths{"insert $data_type"} = $dbh->prepare("INSERT INTO cif_lite_$data_type (uuid, 
                                                                                 value, 
                                                                                 first_seen,
                                                                                 last_seen,
                                                                                 source_id,
                                                                                 impact_id,
                                                                                 severity_enum,
                                                                                 confidence,
                                                                                 description) VALUES (?,?,?,?,?,?,?,?,?)")
    	                         or die "[ERROR] Preparing CIF $data_type Insert statement: " . $dbh->errstr . "\n";
    	                         
    # Update CIF data
    $sths{"update $data_type"} = $dbh->prepare("UPDATE cif_lite_$data_type SET last_seen=?, severity_enum=?, confidence=?, description=? WHERE uuid=?")
     							 or die "[ERROR] Preparing cif data Update statement: " . $dbh->errstr . "\n";
     							 
    # Insert Recent
    $sths{"insert recent $data_type"} = $dbh->prepare("INSERT INTO cif_recent_$data_type (data_uuid, add_timestamp) VALUES (?,?)")
                                        or die "[ERROR] preparing cif recent $data_type Insert statement: " . $dbh->errstr . "\n"; 
                                                               
  }
  		
  $sths{"insert relation"} = $dbh->prepare("INSERT INTO cif_relations (relation_uuid, entity_type, entity_uuid) VALUES (?,?,?)")
                             or die "[ERROR] preparing cif relation insert: " . $dbh->errstr . "\n";		
  
  return \%sths;		
}

###########################
# Get impact lookup values
###########################
sub _get_impacts {
  my $dbh      = shift;
  my $sth_href = shift;

  my %impacts;
  my $retval = ($sth_href->{"select impacts"})->execute or die "[ERROR] executing Impact select statement: " . $dbh->errstr . "\n";
  if (!$retval) {
  	($sth_href->{"select impacts"})->finish;
    return -1;
  } else {
    while ( my $href = ($sth_href->{"select impacts"})->fetchrow_hashref() ) {
      $impacts{ $href->{'impact'} } = $href->{'id'};
      print "[DEBUG] Loading impact " . $href->{'impact'} . ".\n";
    }
    ($sth_href->{"select impacts"})->finish;
  }
  return \%impacts;  
}

##########################
# Add impact lookup value
##########################
sub _add_impact {
  my $dbh      = shift;
  my $sth_href = shift;
  my $impact   = shift;

  my $select_retval  = ($sth_href->{"select impact id"})->execute or die "[ERROR] executing Impact Id select statement: " . $dbh->errstr . "\n";
  my $select_id_href = ($sth_href->{"select impact id"})->fetchrow_arrayref();
  my $next_impact_id = 1;
  if ($select_id_href) {
    $next_impact_id = ($select_id_href->[0]) + 1;
  } 
  ($sth_href->{"select impact id"})->finish; 

  my $retval = ($sth_href->{"insert impacts"})->execute($next_impact_id, $impact); 
  if (!$retval) {
  	($sth_href->{"insert impacts"})->finish;
    my $impacts_href = _get_impacts($dbh, $sth_href);
    if (exists $impacts_href->{$impact}) {
      return $impacts_href->{$impact};
    } 
    return -1;
  } else {
    return $next_impact_id;
    #my $rowval = ($sth_href->{"insert impacts"})->fetchrow_hashref();
    #($sth_href->{"insert impacts"})->finish;
    #print "[DEBUG] Adding impact " . $impact . " (" . $rowval->{'id'} . ").\n"; 
    #return $rowval->{'id'};
  }
}

###########################
# Get source lookup values
###########################
sub _get_sources {
  my $dbh      = shift;
  my $sth_href = shift;

  my %sources;
  my $retval = ($sth_href->{"select sources"})->execute or die "[ERROR] executing Source select statement: " . $dbh->errstr . "\n";
  if (!$retval) {
    ($sth_href->{"select sources"})->finish;
    return -1;
  } else {
    while ( my $href = ($sth_href->{"select sources"})->fetchrow_hashref() ) {
      $sources{ $href->{'source'} } = $href->{'id'};
      print "[DEBUG] Loading source " . $href->{'source'} . ".\n";
    }
    ($sth_href->{"select sources"})->finish;
  }
  return \%sources;  
}

##########################
# Add source lookup value
##########################
sub _add_source {
  my $dbh      = shift;
  my $sth_href = shift;
  my $source   = shift;

  my $select_retval  = ($sth_href->{"select source id"})->execute or die "[ERROR] executing Source Id select statement: " . $dbh->errstr . "\n";
  my $select_id_href = ($sth_href->{"select source id"})->fetchrow_arrayref();
  my $next_source_id = 1;  
  if ($select_id_href) {
    $next_source_id = ($select_id_href->[0]) + 1;
  }
  ($sth_href->{"select source id"})->finish; 

  my $retval = ($sth_href->{"insert sources"})->execute($next_source_id, $source); 
  if (!$retval) {
    ($sth_href->{"insert sources"})->finish;
    my $sources_href = _get_sources($dbh, $sth_href);
    if (exists $sources_href->{$source}) {
      return $sources_href->{$source};
    }
    return -1;
  } else {
    return $next_source_id;
    #my $rowval = ($sth_href->{"insert sources"})->fetchrow_hashref();
    #($sth_href->{"insert sources"})->finish;
    #print "[DEBUG] Adding source " . $source . " (" . $rowval->{'id'} . ").\n";
    #return $rowval->{'id'}; 
  }
}

################
# Store Record
################
sub _store_record {
	my $dbh      = shift;
	my $sth_href = shift;
	my $rec_href = shift;
	my $ret_val  = 0;
	
	my $insert_sth_key = "insert " . $rec_href->{'type'};
	if (!exists $sth_href->{$insert_sth_key}) {
		print "[ERROR] No insert SQL statement exists for record type " . $rec_href->{'type'} . ".\n";	
		return -1;
	}
	
	my $insert_response = ($sth_href->{$insert_sth_key})->execute( $rec_href->{'uuid'},
        				  									   $rec_href->{'value'},
        		   		  	       							   $rec_href->{'first_seen'},
        					       							   $rec_href->{'last_seen'},
        		  			       							   $rec_href->{'source_id'},
        					       							   $rec_href->{'impact_id'},
        					       							   $rec_href->{'severity_enum'},
        					       							   $rec_href->{'confidence'},
        					       							   $rec_href->{'description'} );
   		
	if (!$insert_response) {

		my $update_sth_key = "update " . $rec_href->{'type'};
		if (!exists $sth_href->{$update_sth_key}) {
			print "[ERROR] No update SQL statement exists for record type " . $rec_href->{'type'} . ".\n";	
			return -2;
		}
		
        my $update_response = ($sth_href->{$update_sth_key})->execute( $rec_href->{'last_seen'},
   					  	         $rec_href->{'severity_enum'},
   						         $rec_href->{'confidence'},
   						         $rec_href->{'description'},
   						         $rec_href->{'uuid'} )
                              or die "[ERROR] executing CIF Lite update statement: " . $dbh->errstr . ".\n";
   	
          if (!$update_response) {
            print "[DEBUG, ERROR] trying to insert/update data record: " . $dbh->errstr . "\n";
          }
          else {
            print "[DEBUG] UPDATED " . $rec_href->{'uuid'} . " -- " . $rec_href->{'value'} . ".\n";
            $ret_val = 1;
          }   			
      }
      else {
        # Insert succeeded, add as recent addition
        my $recent_sth_key = "insert recent " . $rec_href->{'type'};
        if (!exists $sth_href->{$recent_sth_key}) {
        	print "[ERROR] No recent insert SQL statement exists for record type " . $rec_href->{'type'} . ".\n";	
			return -3;
		}
        
        my $dt = DateTime->now();
        my $current_timestamp = $dt->datetime();
        my $recent_insert_retval = ($sth_href->{$recent_sth_key})->execute( $rec_href->{'uuid'},
                                                                        $current_timestamp )
                                   or print "[ERROR] executing CIF Lite recent insert statement: " . $dbh->errstr . "\n";
        if (!$recent_insert_retval) {
            print "[DEBUG, ERROR] trying to insert recent data record: " . $dbh->errstr . "\n";
        }
        else {
          print "[DEBUG] INSERTED " . $rec_href->{'uuid'} . " -- " . $rec_href->{'value'} . ".\n";
          $ret_val = 2;
        }
      }
      
      return $ret_val;
}

##################
# Store Relations
##################
sub _store_relations {
	my $dbh       = shift;
	my $sth_href  = shift;
	my $recs_aref = shift;
	
	my $value_string_cat = '';
	foreach my $rec_href (@$recs_aref) {
		$value_string_cat .= $rec_href->{'value'};
	}
	my $relation_uuid = _build_uuid($value_string_cat, '', '');
	
	foreach my $rec_href (@$recs_aref) {
		my $sth_response = ($sth_href->{"insert relation"})->execute( $relation_uuid, 
																	  $_RECTYPE_ENUM{ $rec_href->{'type'} },
																	  $rec_href->{'uuid'}, 
																	) or print "[ERROR] executing CIF Lite relation insert statement: " . $dbh->errstr . "\n";
	}
}

####################
# Normalize Records
####################
sub _normalize_records {
	my $dbh         = shift;
	my $sth_href    = shift;
	my $impact_href = shift;
	my $source_href = shift;
	my $rec_href    = shift;
	
	my @nrecs;
	
	foreach my $rec_type (keys %_RECTYPE_ENUM) {
		if (exists $rec_href->{$rec_type}) {
			my $nrec_href = _normalize_record($dbh, $sth_href, $rec_type, $impact_href, $source_href, $rec_href);
			unless ($nrec_href < 0) {
				push(@nrecs, $nrec_href);
			}
		}
	}

	return \@nrecs;	
}

####################
# Normalize Record
####################
sub _normalize_record {
  my $dbh         = shift;
  my $sth_href    = shift;
  my $value_key   = shift;
  my $impact_href = shift;
  my $source_href = shift;
  my $rec         = shift;

  my %nrec; ## normalized records
  
  ## Record type
  if (exists $_RECTYPE_ENUM{$value_key}) {
    $nrec{'type'} = $value_key;
  } else {
  	print "[ERROR] unknown record type.\n";
  	return -1;
  }	

  ## Get source id from source_href
  if (exists $rec->{'source'}) {
    if (exists $source_href->{ $rec->{'source'} }) {
      $nrec{'source_id'} = $source_href->{ $rec->{'source'} };
    }
    else {
      ## or add it if it doesn't exist
      my $source_id = _add_source($dbh, $sth_href, $rec->{'source'});
      if ($source_id > -1) {
        $nrec{'source_id'} = $source_id;
      } else {
        print "[DEBUG, ERROR] unable to add source " . $rec->{'source'} . ".\n"; 
        return -2; 
      }
    }
  } else {
    print "[DEBUG, ERROR] source field does not exist in CIF record.\n"; 
    return -3; 
  }

  ## Get impact id from impact_href
  if (exists $rec->{'impact'}) {
    if (exists $impact_href->{ $rec->{'impact'} }) {
      $nrec{'impact_id'} = $impact_href->{ $rec->{'impact'} };
    }
    else {
      ## or add it if it doesn't exist
      my $impact_id = _add_impact($dbh, $sth_href, $rec->{'impact'});
      if ($impact_id > -1) {
        $nrec{'impact_id'} = $impact_id;
      } else {
        print "[DEBUG, ERROR] unable to add impact " . $rec->{'impact'} . "\n";  
        return -4; 
      }
    }
  } else {
    print "[DEBUG, ERROR] impact field does not exist in CIF record.\n"; 
    return -5; 
  }  

  ## Record value based on key name (domain, url, etc.)
  if (exists $rec->{$value_key}) {
    if (defined $rec->{$value_key}) {    
      $nrec{'value'} = $rec->{$value_key};
    }
    else { return -6; }
  } else { 
    print "[DEBUG, ERROR] a value field does not exist in CIF record.\n";
    return -6; 
  }

  ## Make sure the value has some sort of length
  if (length($nrec{'value'}) < $_MIN_VALUE_LENGTH) {
    print "[DEBUG, ERROR] value ('" . $nrec{'value'} . "') does not meet minimum length requirement.\n"; 
    return -7; 
  }

  ## UUID based on (value,source,impact)
  my $uuid_str = _build_uuid($nrec{'value'},
                             $nrec{'source_id'},
                             $nrec{'impact_id'});
  if ($uuid_str =~ /[0-9a-f\-]+/i) {
    $nrec{'uuid'} = $uuid_str;
  }  else {
    print "[DEBUG, ERROR] UUID incorrectly created: $uuid_str.\n"; 
    return -8; 
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
    if (exists $_SEVERITY_ENUM{ $rec->{'severity'} }) {
      $nrec{'severity_enum'} = $_SEVERITY_ENUM{ $rec->{'severity'} };
    } else { 
      $nrec{'severity_enum'} = $_SEVERITY_ENUM{'undef'}; 
    }
  } else {
    $nrec{'severity_enum'} = $_SEVERITY_ENUM{'undef'};
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
