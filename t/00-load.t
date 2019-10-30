#!perl -T
use 5.010;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'FTN::Crypt' ) || print "Bail out!\n";
}

diag( "Testing FTN::Crypt $FTN::Crypt::VERSION, Perl $], $^X" );
