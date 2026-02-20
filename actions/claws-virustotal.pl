#!/usr/bin/perl
# Jan Willamowius <jan@willamowius.de>, 2026-02-20
use strict;
use warnings;
use utf8;
use Email::MIME;
use Digest::MD5 qw(md5_hex);
use WWW::Curl::Easy;

my $VIRUSTOTAL_API_KEY = $ENV{'VIRUSTOTAL_API_KEY'} || '';

if ($VIRUSTOTAL_API_KEY eq '') {
	print "VirusTotal API key missing, put it into the VIRUSTOTAL_API_KEY environment variable.\n";
	exit(0); # 0 so we don't mark everything as a virus
}

# read message from STDIN
my $message = '';
while (<>) {
	$message .= $_
}

my $parsed = Email::MIME->new($message);

exit(find_application_part($parsed));

sub find_application_part {
	my $obj = shift;
	my $result = 0;
	foreach my $part ($obj->subparts) {
		my $type = $part->content_type;
		if ($type =~ /^application\//) {
			my $checksum = md5_hex($part->body);
			$result = validate_checksum($checksum);
			return $result if ($result > 0);
		}
		$result = find_application_part($part) if ($type =~ /^multipart/);
		return $result if ($result > 0);
	}
	return 0;
}

sub validate_checksum {
	my $checksum = shift;
	my $curl = WWW::Curl::Easy->new;
    my @myheaders = ('Accept: application/json', "x-apikey: $VIRUSTOTAL_API_KEY");
    $curl->setopt(CURLOPT_HTTPHEADER, \@myheaders);
    $curl->setopt(CURLOPT_TIMEOUT, 60);
    $curl->setopt(CURLOPT_URL, "https://www.virustotal.com/api/v3/files/$checksum");
    my $response;
    $curl->setopt(CURLOPT_WRITEDATA, \$response);
    $curl->setopt(CURLOPT_ACCEPT_ENCODING, 'gzip, deflate');
    my $retcode = $curl->perform;
	return 0 if ($retcode != 0); # can't reach virustotal.com, no way to tell if the file is good or bad, let it pass
	return 0 if ($curl->getinfo(CURLINFO_HTTP_CODE) == 404); # they have never seen this signature, so probably not a virus
	if ($response =~ /\{"error": \{"code": "[^"]+", "message": "([^"]+)"\}\}/) {
		my $msg = $1;
		print "API error: $msg\n";
		return 0;
	}
	if ($response =~ /"last_analysis_stats".*?"malicious":\s*([0-9]+),/) {
		my $num_malicious = $1;
		if ($num_malicious > 0) {
			my $virus_name = 'unknown';
			if ($response =~ /"suggested_threat_label".*?"([^"]+)"/) {
				$virus_name = $1;
			}
			print "Found virus: $virus_name\n";
			return 1; # virus
		}
	}
	return 0; # OK
}

