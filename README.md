# FTN::Crypt
Perl library for the encryption of the FTN messages.

The possibility of FTN netmail encryption may be sometimes a useful option.
Corresponding nodelist flag was proposed in FSC-0073.

Although current FidoNet Policy (version 4.07 dated June 9, 1989) clearly
forbids routing of encrypted traffic without the express permission of
all the links in the delivery system, it's still possible to deliver such
messages directly. And, obviously, such routing may be allowed in FTN
networks other than FidoNet.

The proposed nodelist userflag is ENCRYPT:\[TYPE\], where \[TYPE\] is one of
'PGP2', 'PGP5', 'GnuPG'. So encryption-capable node should have something
like U,ENCRYPT:PGP5 in his nodelist record.

## Synopsis

```
use FTN::Crypt;

$cr = FTN::Crypt->new(
    Nodelist => 'nodelist/NODELIST.*',
) or die FTN::Crypt->error;

$msg_enc = $cr->encrypt_message(
    Address => $ftn_address,
    Message => $msg_raw,
) or die $cr->error;

$msg_dec = $cr->decrypt_message(
    Address    => $ftn_address,
    Message    => $msg_enc,
    Passphrase => $passphrase,
) or die $cr->error;
```

## Author

Petr Antonov, <petr@antonov.space>

## Copyright and license

Copyright (C) 2019 by Petr Antonov

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl 5.10.0. For more details, see the full text
of the licenses at https://opensource.org/licenses/Artistic-1.0, and
http://www.gnu.org/licenses/gpl-2.0.html.

This package is provided "as is" and without any express or implied
warranties, including, without limitation, the implied warranties of
merchantability and fitness for a particular purpose.

## Installation

Using cpan:

```
$ cpan FTN::Crypt
```

Manual install:

```
$ perl Makefile.PL
$ make
$ make install
```

## References

1. [FidoNet Policy Document Version 4.07](https://www.fidonet.org/policy4.txt)
2. [FTS-5001 - Nodelist flags and userflags](http://ftsc.org/docs/fts-5001.006)
3. [FSC-0073 - Encrypted message identification for FidoNet *Draft I*](http://ftsc.org/docs/fsc-0073.001)
