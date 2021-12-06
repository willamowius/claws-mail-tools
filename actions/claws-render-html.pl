#!/usr/bin/perl
#
# Jan Willamowius <jan@willamowius.de>, 2021-11-06
# based on a script from
# Wolfgang Rosner, wrosner@tirnet.de
# oct 2016
# try to extract header and HTML from claws mail files
# and pipe them to pdf generator

use strict;
use warnings;
use Email::MIME;
use File::Temp qw(tempfile);

# ======== some config here: ===========

# list of headers to print
my @headlist = qw(From To cc bcc Date Subject);

# find your favourite pdf viewer
#my $pdfviewer = `which okular` or die ("pdfviewer not found");
my $pdfviewer = `which evince` or die ("pdfviewer not found");
chomp $pdfviewer;

my $wh2p = `which wkhtmltopdf` or die ("wkhtmltopdf not installed");
chomp $wh2p;

# ============= end of config - no user change below =============

# read message from STDIN
my $message = '';
while (<>) {
	$message .= $_
}

my $parsed = Email::MIME->new($message);
my $content_type = $parsed->content_type;

#print "=== debug structure: ===\n";
#print $parsed->debug_structure;
#print "=====================\n";

# collect header lines according to configured @headlist
my @hl_str = ();
foreach my $headitem (@headlist) {
	my @headtxl = $parsed->header($headitem) ;
	foreach my $htlitem (@headtxl) {
		push @hl_str , sprintf ("%s: %s", $headitem, $htlitem) ;
	}
}

# produce some basic html
my $htmlheadstr  = "<hr><br><font size='3'><b>";
my $headerline; 

# with the header lines 
foreach $headerline (@hl_str) {
  $htmlheadstr .= $headerline ;
  $htmlheadstr .= "<br>\n";
}

$htmlheadstr .= "</b></font>";
$htmlheadstr .= "<br><hr><br>\n";

# search for HTML part
my $body = find_html_part($parsed);
$body = $parsed->body if (!$body);
$body = '<h1>No HTML part found!</h1>' if (!$body);

my (undef, $tmp_pdf) = tempfile(UNLINK => 0, SUFFIX => '.pdf'); # put PDF in tempfile for viewers like evince that can't read STDIN

# pipe the stuff through converter
open(PDFPIPE, "| $wh2p - $tmp_pdf 2> /dev/null") or die "Couldn't fork: $!\n";

print PDFPIPE $htmlheadstr . $body;
close(PDFPIPE);

system("$pdfviewer $tmp_pdf");
unlink($tmp_pdf);

sub find_html_part {
	my $obj = shift;
	foreach my $part ($obj->subparts) {
		my $ct = $part->content_type;
		if ($ct =~ /^text\/html/) {
			# TODO: parse charset= if present and recode ?
			return $part->body;
		}
		my $b = find_html_part($part) if ($ct =~ /^multipart/);
		return $b if ($b); # return with first HTML part, otherwise continue to loop
	}
	return undef;
}

