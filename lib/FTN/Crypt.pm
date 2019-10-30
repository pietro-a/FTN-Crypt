# FTN::Crypt - Encryption of the FTN messages
#
# Copyright (C) 2019 by Petr Antonov
#
# This library is free software; you can redistribute it and/or modify it
# under the same terms as Perl 5.10.0. For more details, see the full text
# of the licenses at https://opensource.org/licenses/Artistic-1.0, and
# http://www.gnu.org/licenses/gpl-2.0.html.
#

This package is provided "as is" and without any express or implied
warranties, including, without limitation, the implied warranties of
merchantability and fitness for a particular purpose.

package FTN::Crypt;

use strict;
use warnings;
use 5.010;

our $VERSION = 0.01;

use Carp;

use Crypt::OpenPGP;
use Crypt::OpenPGP::Armour;

use FTN::Crypt::Constants;
use FTN::Crypt::Msg;
use FTN::Crypt::Nodelist;

#----------------------------------------------------------------------#
my $DEFAULT_KEYSERVER = 'zimmermann.mayfirst.org';

#----------------------------------------------------------------------#
sub new {
    my ($class, %opts) = @_;

    die "No options specified" unless %opts;

    my $self = {
        nodelist => FTN::Crypt::Nodelist->new(
            Nodelist => $opts{Nodelist},
        ),
        keyserver => $opts{Keyserver} ? $opts{Keyserver} : $DEFAULT_KEYSERVER,
        pubring => $opts{Pubring},
        secring => $opts{Secring},
    };

    $self = bless $self, $class;
    return $self;
}

#----------------------------------------------------------------------#
sub encrypt_message {
    my ($self, %opts) = @_;

    my $msg = FTN::Crypt::Msg->new(
        Address => $opts{Address},
        Message => $opts{Message},
    );

    my $res = {
        ok => 0,
        msg => '',
    };

    my ($addr, $method) = $self->{nodelist}->get_email_addr($msg->get_address);
    unless ($addr) {
        $res->{msg} = 'Encryption-capable address not found';
        return $res;
    }

    my $pgp = Crypt::OpenPGP->new(
        Compat => $method,
        PubRing => $self->{pubring},
        KeyServer => $self->{keyserver},
        AutoKeyRetrieve => 1,
    );

    die Crypt::OpenPGP->errstr unless $pgp;

    my $recip_cb = sub {
        my ($keys) = @_;

        my @valid_keys = grep { $_->can_encrypt; } @{$keys};

        return \@valid_keys;
    };

    my $msg_enc = $pgp->encrypt(
        Data => $msg->get_text,
        Recipients => $addr,
        RecipientsCallback => $recip_cb,
        Armour => 0,
    );
    if ($msg_enc) {
        $res->{ok} = 1;
        $msg->set_text($msg_enc);
        $msg->add_kludge("$FTN::Crypt::Constants::ENC_MESSAGE_KLUDGE: $method");
        $res->{msg} = $msg->get_message;
    } else {
        $res->{msg} = $pgp->errstr;
        return $res;
    }

    return $res;
}

#----------------------------------------------------------------------#
sub decrypt_message {
    my ($self, %opts) = @_;

    croak "No options specified" unless %opts;
    croak "No passphrase specified" unless defined $opts{Passphrase};

    my $msg = FTN::Crypt::Msg->new(
        Address => $opts{Address},
        Message => $opts{Message},
    );

    my $res = {
        ok => 0,
        msg => '',
    };

    my $method_used;
    foreach my $k (@{$msg->get_kludges}) {
        $method_used = $1 if $k =~ /^$FTN::Crypt::Constants::ENC_MESSAGE_KLUDGE:\s+(\w+)$/;
    }

    unless ($method_used) {
        $res->{msg} = "Message seems not to be encrypted";
        return $res;
    }

    my ($addr, $method) = $self->{nodelist}->get_email_addr($msg->get_address);
    unless ($addr) {
        $res->{msg} = 'Encryption-capable address not found';
        return $res;
    }

    if ($method ne $method_used) {
        $res->{msg} = "Message is encrypted with $method_used while node uses $method";
        return $res;
    }

    my $pgp = Crypt::OpenPGP->new(
        Compat => $method,
        SecRing => $self->{secring},
        AutoKeyRetrieve => 0,
    );

    die Crypt::OpenPGP->errstr unless $pgp;

    my $unarm = Crypt::OpenPGP::Armour->unarmour($msg->get_text);
    unless ($unarm) {
        $res->{msg} = "Unable to unarmour message: " . Crypt::OpenPGP::Armour->errstr;
        return $res;
    }

    my $msg_dec = $pgp->decrypt(
        Data => $unarm->{Data},
        Passphrase => $opts{Passphrase},
    );
    if ($msg_dec) {
        $res->{ok} = 1;
        $msg->set_text($msg_dec);
        $msg->remove_kludge($FTN::Crypt::Constants::ENC_MESSAGE_KLUDGE);
        $res->{msg} = $msg->get_message;
    } else {
        $res->{msg} = $pgp->errstr;
        return $res;
    }

    return $res;
}

1;
__END__

=head1 NAME

FTN::Crypt - Encryption of the FTN messages.

=head1 SYNOPSIS

    use FTN::Crypt;

    $cr = FTN::Crypt->new(
        Nodelist => 'nodelist/NODELIST.*',

        Pubring => '/home/user/.gnupg/pubring.gpg',
        Secring => '/home/user/.gnupg/secring.gpg',
    );
    
    $cr->encrypt_message(
        Address => $ftn_address,
        Message => $msg_raw,
    );

=head1 DESCRIPTION

The possibility of FTN netmail encryption may be sometimes a useful option.
Corresponding nodelist flag was proposed in FSC-0073.

Although current FidoNet Policy (version 4.07 dated June 9, 1989) clearly
forbids routing of encrypted traffic without the express permission of
all the links in the delivery system, it's still possible to deliver such
messages directly. And, obviously, such routing may be allowed in FTN
networks other than FidoNet.

The proposed nodelist userflag is ENCRYPT:[TYPE], where [TYPE] is one of
'PGP2', 'PGP5', 'GnuPG'. So encryption-capable node should have something
like U,ENCRYPT:PGP5 in his nodelist record.

=head1 AUTHOR

Petr Antonov, E<lt>petr@antonov.spaceE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2019 by Petr Antonov

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl 5.10.0. For more details, see the full text
of the licenses at L<https://opensource.org/licenses/Artistic-1.0>, and
L<http://www.gnu.org/licenses/gpl-2.0.html>.

This package is provided "as is" and without any express or implied
warranties, including, without limitation, the implied warranties of
merchantability and fitness for a particular purpose.

=head1 INSTALLATION

Using C<cpan>:

    $ cpan FTN::Crypt

Manual install:

    $ perl Makefile.PL
    $ make
    $ make install

=head1 REFERENCES

=over 4

=item 1 L<FidoNet Policy Document Version 4.07|https://www.fidonet.org/policy4.txt>

=item 2 L<FTS-5001 - Nodelist flags and userflags|http://ftsc.org/docs/fts-5001.006>

=item 3 L<FSC-0073 - Encrypted message identification for FidoNet *Draft I*|http://ftsc.org/docs/fsc-0073.001>

=back 

=cut
(END)
