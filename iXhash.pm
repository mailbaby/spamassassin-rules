=head1 NAME
Mail::SpamAssassin::Plugin::iXhash - compute fuzzy checksums from mail bodies and compare to known spam ones via DNS
=head1 SYNOPSIS
loadplugin    Mail::SpamAssassin::Plugin::iXhash /path/to/iXhash.pm
# Timeout in seconds - default is 10 seconds
ixhash_timeout                  10

# Should we add the hashes to the messages' metadata for later re-use
# Default is not to cache hashes (i.e. re-compute them for every check)
use_ixhash_cache                0

# wether to only use perl (ixhash_pureperl = 1) or the system's 'tr' and 'md5sum'
# Default is to use Perl only
ixhash_pureperl                 1

# If you should have 'tr' and/or 'md5sum' in some weird place (e.g on a Windows server)
# or you want to specify which version to use you can specifiy the exact paths here
# Default is to have SpamAssassin find the executables
ixhash_tr_path          "/usr/bin/tr"
ixhash_md5sum_path      "/usr/bin/md5sum"

# The actual rule
body          IXHASH eval:ixhashtest('ix.dnsbl.manitu.net')
describe      IXHASH This mail has been classified as spam @ iX Magazine, Germany
tflags        IXHASH net
score         IXHASH 1.5


=head1 DESCRIPTION

iXhash.pm is a plugin for SpamAssassin 3.0.0 and up. It takes the body of a mail, strips parts from it and then computes a hash value
from the rest. These values will then be looked up via DNS to see if the hashes have already been categorized as spam by others.
This plugin is based on parts of the procmail-based project 'NiX Spam', developed by Bert Ungerer.(un@ix.de)
For more information see http://www.heise.de/ix/nixspam/. The procmail code producing the hashes only can be found here:
ftp://ftp.ix.de/pub/ix/ix_listings/2004/05/checksums

To see which DNS zones are currently available see http://www.ixhash.net


=cut

package Mail::SpamAssassin::Plugin::iXhash;

use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util;
use Digest::MD5 qw(md5_hex);
use Net::DNS;

our @ISA = qw(Mail::SpamAssassin::Plugin);
our $VERSION = "1.5.5";

sub new {
    my ($class, $mailsa) = @_;
    my $self = $class->SUPER::new($mailsa);
    bless $self, $class;

    if ($mailsa->{local_tests_only}) {
        dbg("IXHASH: Local tests only, disabling iXhash plugin");
        $self->{iXhash_available} = 0;
    } else {
        dbg("IXHASH: Using iXhash plugin $VERSION");
        $self->{iXhash_available} = 1;
    }

    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("ixhashtest");
    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    
    my @settings = (
        { setting => 'ixhash_timeout', default => 10, type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC },
        { setting => 'use_ixhash_cache', default => 0, type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC },
        { setting => 'ixhash_pureperl', default => 1, type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC },
        { setting => 'ixhash_tr_path', type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING },
        { setting => 'ixhash_md5sum_path', type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING }
    );
    
    $conf->{parser}->register_commands(\@settings);
}


sub ixhashtest {
    my ($self, $msg_status, @dnszone) = @_;

    my $dnszone = join('', grep { defined && !ref($_) } @dnszone);
    $dnszone =~ s/[^a-zA-Z0-9.-]//g; 
    $dnszone =~ s/\s+//g;            

    dbg("IXHASH: ixhashtest() called with DNS zone '$dnszone'");

    my $resolver = Net::DNS::Resolver->new;
    my $body = $msg_status->{msg}->get_pristine_body();

    my @hash_methods = (\&compute1sthash, \&compute2ndhash, \&compute3rdhash);
    my $hash_used = 0;

    foreach my $i (0..$#hash_methods) {
        my $compute_hash = $hash_methods[$i];
        my $digest = $compute_hash->($body);

        if (!$digest) {
            dbg("IXHASH: Hash method #" . ($i + 1) . " not computed - requirements not met");
            next;
        }

        dbg("IXHASH: Computed digest (Method #" . ($i + 1) . "): $digest");
        $hash_used++;
        my $result = query_dns_for_hash($digest, $dnszone, $resolver);
        
        if ($result) {
            dbg("IXHASH: Hash matched in DNSBL ($digest) - Method #" . ($i + 1) . ")");
            return 1;
        }
    }

    if ($hash_used == 0) {
        dbg("IXHASH: ERROR: No hashes were computed!");
    }

    dbg("IXHASH: No hash match found, returning 0");
    return 0;
}

sub get_cached_or_compute_hash {
    my ($msg_status, $body, $method_number, $compute_sub) = @_;
    my $key = "X-iXhash-hash-$method_number";
    
    if ($msg_status->{main}->{conf}->{use_ixhash_cache} && $msg_status->{msg}->get_metadata($key)) {
        return $msg_status->{msg}->get_metadata($key);
    }
    
    my $digest = $compute_sub->($body);
    $msg_status->{msg}->put_metadata($key, $digest) if $msg_status->{main}->{conf}->{use_ixhash_cache};
    return $digest;
}

sub query_dns_for_hash {
    my ($digest, $dnszone, $resolver) = @_;

    return 0 unless defined $digest && defined $dnszone;

    # Strip anything that is not a valid MD5 hash or a proper domain
    $digest =~ s/[^a-fA-F0-9]//g;    # Keep only hex characters
    $dnszone =~ s/[^a-zA-Z0-9.-]//g; # Keep only valid domain characters
    $dnszone =~ s/\s+//g;            # Remove spaces

    # Ensure we are ONLY querying the hash
    if (length($digest) != 32) {
        dbg("IXHASH: ERROR: Digest '$digest' is not a valid 32-character MD5 hash");
        return 0;
    }

    my $query = "$digest.$dnszone";
    dbg("IXHASH: Querying DNS for $query");

    my $answer = $resolver->search($query, "A", "IN");
    if (!$answer) {
        dbg("IXHASH: DNS query failed or returned no results for $query");
        return 0;
    }

    foreach my $rr ($answer->answer) {
        return 1 if $rr->type eq "A" && $rr->address =~ /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    }

    return 0;
}


sub compute1sthash {
    my ($body) = @_;
    $body =~ s/\s{100,}/ /g;
    $body =~ s/\s+/ /g;
    $body =~ s/\P{Graph}+//g;
    return md5_hex($body);
}

sub compute2ndhash {
    my ($body) = @_;

    # Check if the email body contains at least 3 of the special characters
    if ($body =~ /((([<>\(\)\|@\*'!?,])|(:\/)).*?){3,}/m) {
        my $body_copy = $body;
        $body_copy =~ s/[[:cntrl:][:alnum:]%&#;=]+//g;
        $body_copy =~ tr/_/./;
        $body_copy =~ s/([[:print:]]{100})(?:\1+)/$1/g;
        $body_copy =~ s/([[:print:]])(?:\1+)/$1/g;

        my $digest = md5_hex($body_copy);

        # Prevent duplicate hashing with Method #1
        if ($digest eq compute1sthash($body)) {
            dbg("IXHASH: Skipping Hash #2 - Duplicate of Method #1");
            return undef;
        }

        dbg("IXHASH: Computed Hash #2: $digest");
        return $digest;
    }

    dbg("IXHASH: Hash method #2 not computed - requirements not met");
    return undef;
}

sub compute3rdhash {
    my ($body) = @_;

    # Ensure at least 8 non-space characters exist
    unless ($body =~ /[\S]{8}/) {
        dbg("IXHASH: Hash method #3 not computed - not enough non-space characters");
        return undef;
    }

    my $body_copy = $body;
    $body_copy =~ s/[[:cntrl:][:space:]=]+//g;

    my $digest = md5_hex($body_copy);

    # Prevent duplicate hashing with Method #2
    my $hash2 = compute2ndhash($body);
    if (defined $hash2 && $digest eq $hash2) {
        dbg("IXHASH: Skipping Hash #3 - Duplicate of Method #2");
        return undef;
    }

    dbg("IXHASH: Computed Hash #3: $digest");
    return $digest;
}


1;
