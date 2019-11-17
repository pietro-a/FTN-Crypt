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

#----------------------------------------------------------------------#

=head1 NAME

FTN::Crypt::Nodelist - Nodelist processing for the L<FTN::Crypt> module.

=head1 SYNOPSIS

    use FTN::Crypt::Nodelist;

    my $obj = FTN::Crypt::Nodelist->new(
        Nodelist => 'nodelist/NODELIST.*',
        Username => 'user', # optional, defaults to 'sysop'
    );
    my ($addr, $method) = $obj->get_email_addr('99:8877/1');

=cut

#----------------------------------------------------------------------#

use FTN::Address;
use FTN::Crypt::Constants;
use FTN::Nodelist;

#----------------------------------------------------------------------#

my $DEFAULT_USERNAME = 'sysop';

#----------------------------------------------------------------------#

=head1 METHODS

=cut

#----------------------------------------------------------------------#

=head2 new()

Constructor.

=head3 Parameters:

=over 4

=item * C<Nodelist>: Path to nodelist file. If contains wildcard, file with maximum number in digital extension will be selected.

=item * B<Optional> C<Username>: Username part in email address, which corresponds to the FTN one, defaults to 'sysop'.

=back

=head3 Returns:

Created object or error in C<FTN::Crypt::Nodelist-E<gt>error>.

Sample:

    my $obj = FTN::Crypt::Nodelist->new(
        Nodelist => 'nodelist/NODELIST.*',
        Username => 'user', # optional, defaults to 'sysop'
    );

=cut

sub new {
    my $class = shift;
    my (%opts) = @_;

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

=head2 get_email_addr()

If recipient supports PGP encryption, get recipient's email address and encryption method.

=head3 Parameters:

=over 4

=item * Recipient's FTN address.

=back

=head3 Returns:

Recipient's email address and encryption method or error in C<$obj-E<gt>error>.

Sample:

    my ($addr, $method) = $obj->get_email_addr('99:8877/1') or die $obj->error;

=cut

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
