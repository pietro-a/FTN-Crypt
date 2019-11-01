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

use base qw/FTN::Crypt::Error/;

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

    unless (%opts) {
        $class->set_error('No options specified');
        return;
    }
    unless ($opts{Address}) {
        $class->set_error('No address specified');
        return;
    }
    unless ($opts{Message}) {
        $class->set_error('No message specified');
        return;
    }

    my $self = {
        msg => {
            HEADER => [],
            TEXT => '',
            FOOTER => [],
        },
    };

    $self = bless $self, $class;

    unless ($self->set_address($opts{Address})) {
        $class->set_error($self->error);
        return;
    }
    unless ($self->set_message($opts{Message})) {
        $class->set_error($self->error);
        return;
    }

    return $self;
}

#----------------------------------------------------------------------#
sub _check_kludge {
    my $self = shift;
    my ($kludge) = @_;

    unless (defined $kludge && $kludge ne "") {
        $self->set_error('Kludge is empty');
        return;
    }

    return $kludge;
}

#----------------------------------------------------------------------#
sub _check_area {
    my $self = shift;
    my ($area) = @_;

    $area = $DEFAULT_KLUDGE_AREA unless defined $area;
    unless ($KLUDGE_AREAS{$area}) {
        $self->set_error("Invalid kludge area ($area)");
        return;
    }

    return $area;
}

#----------------------------------------------------------------------#
sub add_kludge {
    my $self = shift;
    my ($kludge, $area) = @_;

    $kludge = $self->_check_kludge($kludge);
    $area = $self->_check_area($area);

    if (defined $kludge && defined $area) {
        push @{$self->{msg}->{$area}}, $kludge;
    } else {
        return;
    }

    return 1;
}

#----------------------------------------------------------------------#
sub remove_kludge {
    my $self = shift;
    my ($kludge, $area) = @_;

    $kludge = $self->_check_kludge($kludge);
    $area = $self->_check_area($area);

    if (defined $kludge && defined $area) {
        @{$self->{msg}->{$area}} = grep { !/^${kludge}(?::?\s.+)*$/ }
                                   @{$self->{msg}->{$area}};
    } else {
        return;
    }

    return 1;
}

#----------------------------------------------------------------------#
sub get_kludges {
    my $self = shift;
    my ($area) = @_;

    $area = $self->_check_area($area);
    return unless $area;

    return $self->{msg}->{$area};
}

#----------------------------------------------------------------------#
sub get_address {
    my $self = shift;

    my $addr = $self->{addr}->get;
    unless ($addr) {
        $self->set_error($@);
        return;
    }

    return $addr;
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

    $self->{addr} = FTN::Address->new($addr);
    unless ($self->{addr}) {
        $self->set_error($@);
        return;
    }

    return 1;
}

#----------------------------------------------------------------------#
sub set_text {
    my $self = shift;
    my ($text) = @_;

    $text =~ s/\n/\r/g;
    $self->{msg}->{TEXT} = $text;

    return 1;
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

    return 1;
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
