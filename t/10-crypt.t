#!perl
use 5.010;
use strict;
use warnings;
use Test::LongString lcss => 0;
use Test::More;

plan tests => 8;

use FTN::Crypt;

open my $fin, 't/data/msg.txt' or die $!;
binmode $fin;
my $msg = <$fin>;
close $fin;

my $obj = new_ok('FTN::Crypt', [
    Nodelist => 't/data/nodelist.*',
    Pubring  => 't/data/pubring.gpg',
    Secring  => 't/data/secring.gpg',
], 'Create FTN::Crypt object');

my $encrypted = $obj->encrypt_message(
    Address => '99:8877/2',
    Message => $msg,
);
diag('Encryption error: ', $obj->error) unless defined $encrypted;
isnt($encrypted, undef, 'Encryption');

contains_string($encrypted, 'ENC: PGP5');
contains_string($encrypted, '-----BEGIN PGP MESSAGE-----');

my $decrypted = $obj->decrypt_message(
    Address => '99:8877/2',
    Message => $encrypted,
    Passphrase => 'test passphrase',
);
diag('Decryption error: ', $obj->error) unless defined $decrypted;
isnt($decrypted, undef, 'Decryption');

lacks_string($decrypted, 'ENC: PGP5');
lacks_string($decrypted, '-----BEGIN PGP MESSAGE-----');

is_string($decrypted, $msg, 'Decrypted is the same as original');
