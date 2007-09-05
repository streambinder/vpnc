#! /usr/bin/perl -w

# $Id:$

# Written by Wolfram Sang (wolfram@the-dreams.de) in 2007,
# some inspiration from help2man by Brendan O'Dea and from Perl::Critic

# Generate the vpnc-manpage from a template and the --long-help-output.
# Version 0.1
# TODO: give error when our markers in the template are not found
#       add some comments
#       can the default for 'Application version' differ?

# Command-line options: none
# Files needed        : ./vpnc ./vpnc.8.template ./VERSION
# Files created       : ./vpnc.8
# Exit status         : errno-values

# Distributed under the same licence as vpnc.

use strict;
use Fatal    qw(open close);
use filetest qw(access);
use POSIX    qw(strftime setlocale LC_ALL);

my $vpnc = './vpnc';
-e $vpnc or die "Can't find $vpnc. Did you compile it?\n";
-x $vpnc or die "Can't execute $vpnc. Please check permissions.\n";

open my $LONGHELP, '-|', "$vpnc --long-help";
my $vpnc_opts = '';
my $relative_indent = 0;
my $indent_needed = 0;

while (<$LONGHELP>) {
    if (/^  /) {
	if ($relative_indent) {
	    /^( *)/;
	    if (length($1) < $relative_indent) {
		$vpnc_opts .= ".RE\n";
		$relative_indent = 0;
		$indent_needed = 1;
	    }
	}
	
	if (s/^ *(--[\w-]+)/\n.TP\n.BI "$1"/) {
	    s/(<.+>)/ " $1"/;
	}
	
	s/^ *(\(configfile only option\))/\n.TP\n.B $1/;

	s/^ *(Default:)/.IP\n$1/;

	if (s/^ *(conf-variable:) (.+?) ?([<\n])/.P\n$1\n.BI "$2"$3/) {
	    s/(<.+>)/ " $1"/;
	}

	if (s/^( +)\* /.IP \\(bu\n/) {
	    if (not $relative_indent) {
		$vpnc_opts .= ".RS\n";
	        $relative_indent = length $1;
	    }
	}
	
	if ($indent_needed and not /^\n?\.[TI]?P/) {
	    $vpnc_opts .= ".IP\n";
	    $indent_needed = 0;
	}
	
        s/^ *//;
	s/ *$//;
	s/-/\\-/g;
        $vpnc_opts .= $_;
    }
}
close $LONGHELP;

setlocale( LC_ALL, 'C' );
my $date = strftime( '%B %Y', localtime );

open my $VERSION, '<', './VERSION';
my $vpnc_version = <$VERSION>;
close $VERSION;
chomp $vpnc_version;

open my $TEMPLATE, '<', './vpnc.8.template';
open my $MANPAGE , '>', './vpnc.8';

print {$MANPAGE} <<"END_MANPAGE_HEADER";
.\\" This manpage is generated!
.\\" Please edit the template-file in the source-distribution only.
.TH VPNC "8" "$date" "vpnc version $vpnc_version" "System Administration Utilities"
END_MANPAGE_HEADER

while (<$TEMPLATE>) {
    if ($_ ne ".\\\" ###makeman.pl: Insert options from help-output here!\n") {
	print {$MANPAGE} $_;
    } else {
        print {$MANPAGE} $vpnc_opts;
    }
}

close $TEMPLATE;
close $MANPAGE;
