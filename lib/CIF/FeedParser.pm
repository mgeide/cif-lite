package CIF::FeedParser;

use strict;
use warnings;

use CIF::Utils ':all';
use Regexp::Common qw/net URI/;
use Regexp::Common::net::CIDR;
use Encode qw/encode_utf8/;
use Data::Dumper;
use File::Type;
use threads;
use Module::Pluggable require => 1;
use Digest::MD5 qw/md5_hex/;
use Digest::SHA1 qw/sha1_hex/;
use URI::Escape;

my @processors = __PACKAGE__->plugins;
@processors = grep(/Processor/,@processors);

sub new {
    my ($class,%args) = (shift,@_);
    my $self = {};
    bless($self,$class);

    return $self;
}

sub get_feed { 
    my $f = shift;
    my ($content,$err) = threads->create('_get_feed',$f)->join();
    return(undef,$err) if($err);
    return(undef,'no content') unless($content);
    # auto-decode the content if need be
    $content = _decode($content,$f);

    # encode to utf8
    $content = encode_utf8($content);
    # remove any CR's
    $content =~ s/\r//g;
    delete($f->{'feed'});
    return($content);
}

# we do this sep cause it's in a thread
# this gets around memory leak issues and TLS threading issues with Crypt::SSLeay, etc
sub _get_feed {
    my $f = shift;
    return unless($f->{'feed'});

    foreach my $key (keys %$f){
        foreach my $key2 (keys %$f){
            if($f->{$key} =~ /<$key2>/){
                $f->{$key} =~ s/<$key2>/$f->{$key2}/g;
            }
        }
    }
    my @pulls = __PACKAGE__->plugins();
    @pulls = grep(/::Pull::/,@pulls);
    foreach(@pulls){
        if(my $content = $_->pull($f)){
            return(undef,$content);
        }
    }
    return('could not pull feed',undef);
}


## TODO -- turn this into plugins
sub parse {
    my $class = shift;
    my $f = shift;
    my ($content,$err) = get_feed($f);
    return($err,undef) if($err);

    my $return;
    # see if we designate a delimiter
    if(my $d = $f->{'delimiter'}){
        require CIF::FeedParser::ParseDelim;
        $return = CIF::FeedParser::ParseDelim::parse($f,$content,$d);
    } else {
        # try to auto-detect the file
        if($content =~ /<\?xml version=/){
            if($content =~ /<rss version=/){
                require CIF::FeedParser::ParseRss;
                $return = CIF::FeedParser::ParseRss::parse($f,$content);
            } else {
                require CIF::FeedParser::ParseXml;
                $return = CIF::FeedParser::ParseXml::parse($f,$content);
            }
        } elsif($content =~ /^\[?{/){
            # possible json content or CIF
            if($content =~ /^{"status"\:/){
                require CIF::FeedParser::ParseCIF;
                $return = CIF::FeedParser::ParseCIF::parse($f,$content);
            } elsif($content =~ /urn:ietf:params:xmls:schema:iodef-1.0/) {
                require CIF::FeedParser::ParseJsonIodef;
                $return = CIF::FeedParser::ParseJsonIodef::parse($f,$content);
            } else {
                require CIF::FeedParser::ParseJson;
                $return = CIF::FeedParser::ParseJson::parse($f,$content);
            }
        ## TODO -- fix this; double check it
        } elsif($content =~ /^#?\s?"\S+","\S+"/){
            require CIF::FeedParser::ParseCsv;
            $return = CIF::FeedParser::ParseCsv::parse($f,$content);
        } else {
            require CIF::FeedParser::ParseTxt;
            $return = CIF::FeedParser::ParseTxt::parse($f,$content);
        }
    }
    return(undef,$return);
}

sub _decode {
    my $data = shift;
    my $f = shift;

    my $ft = File::Type->new();
    my $t = $ft->mime_type($data);
    my @plugs = __PACKAGE__->plugins();
    @plugs = grep(/Decode/,@plugs);
    foreach(@plugs){
        if(my $ret = $_->decode($data,$t,$f)){
            return($ret);
        }
    }
    return $data;
}

sub _sort_detecttime {
    my $recs = shift;

    foreach (@{$recs}){
        delete($_->{'regex'}) if($_->{'regex'});
        my $dt = $_->{'detecttime'};
        if($dt){
            $dt = normalize_timestamp($dt);
        }
        unless($dt){
            $dt = DateTime->from_epoch(epoch => time());
            if(lc($_->{'detection'}) eq 'hourly'){
                $dt = $dt->ymd().'T'.$dt->hour.':00:00Z';
            } elsif(lc($_->{'detection'}) eq 'monthly') {
                $dt = $dt->year().'-'.$dt->month().'-01T00:00:00Z';
            } elsif(lc($_->{'detection'} ne 'now')){
                $dt = $dt->ymd().'T00:00:00Z';
            } else {
                $dt = $dt->ymd().'T'.$dt->hms();
            }
        }
        $_->{'detecttime'} = $dt;
        $_->{'description'} = '' unless($_->{'description'});
    }
    ## TODO -- can we get around having to create a new array?
    my @new = sort { $b->{'detecttime'} cmp $a->{'detecttime'} } @$recs;
    return(\@new);
}

## TODO _- clean this up
sub _insert {
    my $f = shift;
    my $dbh = shift;
    my $a = $f->{'address'} || $f->{'md5'} || $f->{'sha1'} || $f->{'malware_md5'} || $f->{'malware_sha1'};
    # protect against feeds that suck and put things like "-" in there
    # you know how the hell you are! >:0
    return(0) unless($a && length($a) > 2);

    foreach my $p (@processors){
        $p->process($f);
    }

    # snag this before it goes through the insert
    # and gets converted to a uuid
    my $source = $f->{'source'};
    my ($err,$id) = $dbh->insert($f);
    ## TODO -- setup a mailer that returns this in cif_feed_parser
    warn($err) unless($id);
    
    $a = substr($a,0,40);
    $a .= '...';
    print $source.' -- '.$id->uuid().' -- '.$f->{'impact'}.' '.$f->{'description'}.' -- '.$a."\n";
    return(0);
}

sub insert {
    my $config = shift;
    my $recs = shift;
    
    ## TODO FIX
    ## when we're using something than localhost, AutoCommit connection pooling doesn't work well
    ## need to make this cleaner with the CIF::Archive and CIF::Archive::Plugin interfaces

    require CIF::Archive;
    my $archive = 'CIF::Archive';
    if($config->{'database'}){
        local $^W = 0;
        eval { $archive->connection(@{$config->{'database'}}) };
        ## TODO -- do a better catching of this
        if($@){
            die($@);
        }
        local $^W = 1;
    }
    ## TODO -- fix
    ## too many transaction deadlocks to use this
    ## will fix in later release.
    #$archive->db_Main->{'AutoCommit'} = 0;

    foreach (@$recs){
        foreach my $key (keys %$_){
            next unless($_->{$key});
            if($_->{$key} =~ /<(\S+)>/){
                my $x = $_->{$1};
                if($x){
                    $_->{$key} =~ s/<\S+>/$x/;
                }
            }
        }
        _insert($_,$archive);
    }

    $archive->dbi_commit() unless($archive->db_Main->{'AutoCommit'});
    return(0);
}

sub process {
    my $class = shift;
    my %args = @_;

    my $threads = $args{'threads'};
    my $recs    = $args{'entries'};
    my $full    = $args{'full_load'};
    my $config  = $args{'config'};

    # we do this so other scripts can hook into us
    my $fctn = ($args{'function'}) ? $args{'function'} : 'CIF::FeedParser::insert';

    # do the sort before we split
    $recs = _sort_detecttime($recs);
    my $batches;
    if($full){ 
        $batches = split_batches($threads,$recs);
    } else {
        # sort by detecttime and only process the last 5 days of stuff
        ## TODO -- make this configurable
        my $goback = DateTime->from_epoch(epoch => (time() - (84600 * 5)));
        $goback = $goback->ymd().'T'.$goback->hms().'Z';
        my @rr;
        foreach (@$recs){
            last if(($_->{'detecttime'} cmp $goback) == -1);
            push(@rr,$_);
        }
        # TODO -- round robin the split?
        $batches = split_batches($threads,\@rr);
    }

    if(scalar @{$batches} == 1){
        ## MWG: note this should be the function $fctn
	#insert($config,$recs);
	##
 	{ # MWG: scope the no strict refs to allow calling function based on string variable 
          no strict "refs";
          &$fctn($config,$recs);
        }
    } else {
        foreach(@{$batches}){
            my $t = threads->create($fctn,$config,$_);
        }

        while(threads->list()){
            my @joinable = threads->list(threads::joinable);
            unless($#joinable > -1){
                sleep(1);
                next();
            }
            foreach(@joinable){
                $_->join();
            }
        }
    }
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

CIF::FeedParser - Perl extension for parsing different types of feeds and inserting into CIF

=head1 SYNOPSIS

  use CIF::FeedParser;
  my $c = Config::Simple->new($config);
  my @items = CIF::FeedParser::parse($c)
  my $full_load = 1;
  CIF::FeedParser::t_insert($full_load,undef,@items);


  my $content = CIF::FeedParser::get_feed($c);
  my @lines = split("\n",$content);
  my @items;
  foreach(@lines){
    # .. do something
    my $h = {
      address => 'example.com',
      portlist => 123,
      %$c,
    };
    push(@items,$h);
  }
  
  CIF::FeedParser::t_insert($full_load,undef,@items);

=head1 SEE ALSO

script/cif_feed_parser for more doc and usage tips

http://code.google.com/p/collective-intelligence-framework

=head1 AUTHOR

Wes Young, E<lt>wes@barely3am.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Wes Young (claimid.con/wesyoung)
Copyright (C) 2011 by REN-ISAC and The Trustees of Indiana University

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
