#!perl -T
use 5.010;
use strict;
use warnings;
use Test::More;

plan tests => 5;

use FTN::Crypt::Nodelist;

my $obj = new_ok('FTN::Crypt::Nodelist', [
    Nodelist => 't/data/nodelist.*',
    Username => 'user',
], 'Create FTN::Crypt::Nodelist object');

my ($addr1, $method1) = $obj->get_email_addr('99:8877/1');
is($addr1, undef, 'Encryption unsupported');

my ($addr2, $method2) = $obj->get_email_addr('99:8877/2');
is($addr2, '<user@f2.n8877.z99.fidonet.net>', 'Got encryption-capable address');
is($method2, 'PGP5', 'Got encryption method');

my ($addr3, $method3) = $obj->get_email_addr('99:8877/3');
is($addr3, undef, 'Node not found');
