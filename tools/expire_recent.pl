#!/usr/bin/perl -w

use strict;
use DBI;
use DateTime;

my $ciflite_dbname = "cif_lite";
my $ciflite_uname  = "postgres";
my $ciflite_pass   = "";
my $ciflite_dbh = DBI->connect("dbi:Pg:dbname=$ciflite_dbname", "$ciflite_uname", "$ciflite_pass")
            or die "Cannot connect: $DBI::errstr\n";

my $expire_after_days = 2;
my $expire_dt = DateTime->now->subtract(days => $expire_after_days);
my $expire_dt_str = $expire_dt->datetime();

my @types = ( 'ip', 'domain', 'url', 'email', 'md5', 'sha1' );
foreach my $type (@types) {
	my $delete_sql = "DELETE FROM cif_recent_$type WHERE add_timestamp < ?";
	my $delete_sth = $ciflite_dbh->prepare($delete_sql);
	my $rows = $delete_sth->execute($expire_dt_str);
	print "[DEBUG] Deleted $rows from cif_recent_$type\n";
	$delete_sth->finish();
}

$ciflite_dbh->disconnect(); 

