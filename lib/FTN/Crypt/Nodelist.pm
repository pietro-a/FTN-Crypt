# FTN::Crypt::Nodelist - Nodelist processing for the FTN::Crypt module
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

package FTN::Crypt::Nodelist;

use strict;
use warnings;
use 5.010;

use base qw/FTN::Crypt::Error/;

use FTN::Address;
use FTN::Crypt::Constants;
use FTN::Nodelist;

#----------------------------------------------------------------------#
my $DEFAULT_USERNAME = 'sysop';

#----------------------------------------------------------------------#
sub new {
    my ($class, %opts) = @_;

    unless (%opts) {
        $class->set_error('No options specified');
        return;
    }
    unless ($opts{Nodelist}) {
        $class->set_error('No nodelist specified');
        return;
    }

    my $self = {
        _username => $DEFAULT_USERNAME,
    };

    $self->{_nodelist} = FTN::Nodelist->new(-file => $opts{Nodelist});
    unless ($self->{_nodelist}) {
        $class->set_error($@);
        return;
    }

    if ($opts{Username}) {
        unless ($opts{Username} =~ /^\w+([\.-]?\w+)*$/) {
            $class->set_error('Invalid username format');
            return;
        }
        $self->{_username} = $opts{Username};
    }

    $self = bless $self, $class;
    return $self;
}

#----------------------------------------------------------------------#
sub get_email_addr {
    my $self = shift;
    my ($ftn_addr) = @_;

    unless ($ftn_addr) {
        $self->set_error('No FTN address specified');
        return;
    }

    my $node = $self->{_nodelist}->getNode($ftn_addr);
    unless ($node) {
        $self->set_error($@);
        return;
    }

    my %flags = map { /:/ ? (split /:/, $_, 2) : ($_ => 1) }
                map { tr/\r\n//dr }
                @{$node->flags};
    unless ($flags{$FTN::Crypt::Constants::ENC_NODELIST_FLAG}) {
        $self->set_error("No encryption nodelist flag ($FTN::Crypt::Constants::ENC_NODELIST_FLAG)");
        return;
    }
    unless ($FTN::Crypt::Constants::ENC_METHODS{$flags{$FTN::Crypt::Constants::ENC_NODELIST_FLAG}}) {
        $self->set_error("Unsupported encryption method ($flags{$FTN::Crypt::Constants::ENC_NODELIST_FLAG})");
        return;
    }
    
    my $addr = FTN::Address->new($node->address);
    unless ($addr) {
        $self->set_error($@);
        return;
    }

    return "<$self->{_username}@" . $addr->fqdn . '>', $flags{$FTN::Crypt::Constants::ENC_NODELIST_FLAG};
}

1;
__END__

=head1 NAME

FTN::Crypt::Nodelist - Nodelist processing for the L<FTN::Crypt> module.

=head1 SYNOPSIS

    use FTN::Crypt::Nodelist;

    my $ndl = FTN::Crypt::Nodelist->new(
        Nodelist => 'nodelist/NODELIST.*',
        Username => 'user', # optional, defaults to 'sysop'
    );
    my ($addr, $method) = $ndl->get_email_addr('2:5020/1');

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
