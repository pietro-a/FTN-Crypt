# FTN::Crypt::Msg - Message parsing for the FTN::Crypt module
#
# Copyright (C) 2019 by Petr Antonov
#
# This library is free software; you can redistribute it and/or modify it
# under the same terms as Perl 5.10.0. For more details, see the full text
# of the licenses at https://opensource.org/licenses/Artistic-1.0, and
# http://www.gnu.org/licenses/gpl-2.0.html.
#
# This package is provided "as is" and without any express or implied
# warranties, including, without limitation, the implied warranties of
# merchantability and fitness for a particular purpose.
#

package FTN::Crypt::Msg;

use strict;
use warnings;
use 5.010;

use Carp;

use FTN::Address;

#----------------------------------------------------------------------#
my $SOH = chr(1);

my $DEFAULT_KLUDGE_AREA = 'HEADER';
my %KLUDGE_AREAS = (
    HEADER => 1,
    FOOTER => 1,
);

#----------------------------------------------------------------------#
sub new {
    my ($class, %opts) = @_;

    croak "No options specified" unless %opts;
    croak "No address specified" unless $opts{Address};
    croak "No message specified" unless $opts{Message};

    my $self = {
        msg => {
            HEADER => [],
            TEXT => '',
            FOOTER => [],
        },
    };

    $self = bless $self, $class;

    $self->set_address($opts{Address});
    $self->set_message($opts{Message});

    return $self;
}

#----------------------------------------------------------------------#
sub _check_kludge {
    my ($kludge, $area) = @_;

    $area = $DEFAULT_KLUDGE_AREA unless defined $area;
    croak "Invalid kludge area" unless $KLUDGE_AREAS{$area};

    croak "Kludge is empty" unless defined $kludge && $kludge ne "";

    return $kludge, $area;
}

#----------------------------------------------------------------------#
sub add_kludge {
    my ($self, $kludge, $area) = @_;

    ($kludge, $area) = _check_kludge($kludge, $area);

    push @{$self->{msg}->{$area}}, $kludge;
}

#----------------------------------------------------------------------#
sub remove_kludge {
    my $self = shift;
    my ($kludge, $area) = @_;

    ($kludge, $area) = _check_kludge($kludge, $area);

    @{$self->{msg}->{$area}} = grep { !/^${kludge}(?::?\s.+)*$/ }
                               @{$self->{msg}->{$area}};
}

#----------------------------------------------------------------------#
sub get_kludges {
    my $self = shift;
    my ($area) = @_;

    $area = $DEFAULT_KLUDGE_AREA unless defined $area;
    croak "Invalid kludge area" unless $KLUDGE_AREAS{$area};

    return $self->{msg}->{$area};
}

#----------------------------------------------------------------------#
sub get_address {
    my $self = shift;
    
    return $self->{addr}->get;
}

#----------------------------------------------------------------------#
sub get_text {
    my $self = shift;

    my $text = $self->{msg}->{TEXT};
    $text =~ s/\r/\n/g;
    
    return $text;
}

#----------------------------------------------------------------------#
sub get_message {
    my $self = shift;

    my @msg;

    push @msg, join "\r", map { "${SOH}$_" } @{$self->{msg}->{HEADER}};
    push @msg, $self->{msg}->{TEXT};
    push @msg, join "\r", map { "${SOH}$_" } @{$self->{msg}->{FOOTER}};

    my $msg_out = join "\r", @msg;
    
    return $msg_out;
}

#----------------------------------------------------------------------#
sub set_address {
    my $self = shift;
    my ($addr) = @_;
    
    $self->{addr} = FTN::Address->new($addr) or croak $!;
}

#----------------------------------------------------------------------#
sub set_text {
    my $self = shift;
    my ($text) = @_;

    $text =~ s/\n/\r/g;
    $self->{msg}->{TEXT} = $text;
}

#----------------------------------------------------------------------#
sub set_message {
    my $self = shift;
    my ($msg) = @_;
    
    my @msg_lines = split /\r/, $msg;
    my $found_text = 0;
    my $finished = 0;
    my @text;
    foreach my $l (@msg_lines) {
        if ($l =~ s/^${SOH}//) {
            my $block = $found_text ? 'FOOTER' : 'HEADER';
            $finished = 1 if $found_text && !$finished;
            push @{$self->{msg}->{$block}}, $l;
        } elsif (!$finished) {
            $found_text = 1 unless $found_text;
            push @text, $l;
        }
    }
    $self->{msg}->{TEXT} = join "\r", @text;
}

1;
__END__

=head1 NAME

FTN::Crypt::Msg - Message parsing for the L<FTN::Crypt> module.

=head1 SYNOPSIS

    use FTN::Crypt::Msg;

    my $msg = FTN::Crypt::Msg->new(
        Address => $ftn_address,
        Message => $msg_src,
    );
    $msg->add_kludge('ENC: PGP5');
    $msg->remove_kludge('ENC');
    my $text = $msg->get_text;
    my $kludges = $msg->get_kludges;
    my $msg_raw = $msg->get_message;

=head1 AUTHOR

Petr Antonov, E<lt>petr _at_ antonov _dot_ spaceE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2019 by Petr Antonov

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl 5.10.0. For more details, see the full text
of the licenses at L<https://opensource.org/licenses/Artistic-1.0>, and
L<http://www.gnu.org/licenses/gpl-2.0.html>.

This package is provided "as is" and without any express or implied
warranties, including, without limitation, the implied warranties of
merchantability and fitness for a particular purpose.
