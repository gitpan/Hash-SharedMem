=head1 NAME

Hash::SharedMem::Handle - handle for efficient shared mutable hash

=head1 SYNOPSIS

	use Hash::SharedMem::Handle;

	if(Hash::SharedMem::Handle->referential_handle) { ...

	$shash = Hash::SharedMem::Handle->open($filename, "rwc");

	if($shash->is_readable) { ...
	if($shash->is_writable) { ...
	$mode = $shash->mode;

	if($shash->getd($key)) { ...
	$value = $shash->get($key);
	$shash->set($key, $newvalue);
	$oldvalue = $shash->gset($key, $newvalue);
	if($shash->cset($key, $chkvalue, $newvalue)) { ...

	$snap_shash = $shash->snapshot;
	if($shash->is_snapshot) { ...

	$shash->idle;
	$shash->tidy;

	$tally = $shash->tally_get;
	$shash->tally_zero;
	$tally = $shash->tally_gzero;

	tie %shash, "Hash::SharedMem::Handle", $shash;
	tie %shash, "Hash::SharedMem::Handle", $filename, "rwc";

	$shash = tied(%shash);
	if(exists($shash{$key})) { ...
	$value = $shash{$key};
	$shash{$key} = $newvalue;
	$oldvalue = delete($shash{$key});

=head1 DESCRIPTION

An object of this class is a handle referring to a memory-mapped shared
hash object of the kind described in L<Hash::SharedMem>.  It can be
passed to the functions of that module, or the same operations can be
performed by calling the methods described below.  Uses of the function
and method interfaces may be intermixed arbitrarily; they are completely
equivalent in function.  They are not equivalent in performance, however,
with the method interface being somewhat slower.

This class also supplies a tied-hash interface to shared hashes.  The tied
interface is much slower than the function and method interfaces.
The behaviour of a tied hash more resembles the function and method
interfaces to shared hashes than it resembles the syntactically-similar
use of ordinary Perl hashes.  Using a non-string as a key will result
in an exception, rather than stringification of the key.  Using a
string containing a non-octet codepoint as a key will also result in an
exception, rather than merely referring to an absent hash element.

=cut

package Hash::SharedMem::Handle;

{ use 5.006; }
use warnings;
use strict;

use Hash::SharedMem ();

our $VERSION = "0.003";

=head1 CLASS METHODS

=over

=item Hash::SharedMem::Handle->referential_handle

Returns a truth value indicating whether each shared hash handle
contains a first-class reference to the shared hash to which it refers.
See L<Hash::SharedMem/"Filesystem referential integrity"> for discussion
of the significance of this.

=back

=head1 CONSTRUCTOR

=over

=item Hash::SharedMem::Handle->open(FILENAME, MODE)

Opens and return a handle referring to a shared hash object,
or C<die>s if the shared hash can't be opened as specified.
See L<Hash::SharedMem/shash_open> for details.

=back

=head1 METHODS

=over

=item $shash->is_readable

=item $shash->is_writable

=item $shash->mode

=item $shash->getd(KEY)

=item $shash->get(KEY)

=item $shash->set(KEY, NEWVALUE)

=item $shash->gset(KEY, NEWVALUE)

=item $shash->cset(KEY, CHKVALUE, NEWVALUE)

=item $shash->snapshot

=item $shash->is_snapshot

=item $shash->idle

=item $shash->tidy

=item $shash->tally_get

=item $shash->tally_zero

=item $shash->tally_gzero

These methods are each equivalent to the corresponding
"C<shash_>"-prefixed function in L<Hash::SharedMem>.  See that document
for details.

=back

=head1 TIE CONSTRUCTORS

=over

=item tie(VARIABLE, "Hash::SharedMem::Handle", SHASH)

I<VARIABLE> must be a hash variable, and I<SHASH> must be a handle
referring to a shared hash object.  The call binds the variable to the
shared hash, so that the variable provides a view of the shared hash
that resembles an ordinary Perl hash.  The shared hash handle is returned.

=item tie(VARIABLE, "Hash::SharedMem::Handle", FILENAME, MODE)

I<VARIABLE> must be a hash variable.  The call opens a handle referring
to a shared hash object, as described in L<Hash::SharedMem/shash_open>,
and binds the variable to the shared hash, so that the variable provides a
view of the shared hash that resembles an ordinary Perl hash.  The shared
hash handle is returned.

=back

=head1 TIED OPERATORS

For all of these operators, the key of interest (I<KEY> parameter)
and values can each be any octet (Latin-1) string.  Strings containing
non-octets (Unicode characters above U+FF) and items other than strings
cannot be used as keys or values.  If a dualvar (scalar with independent
string and numeric values) is supplied, only its string value will
be used.

=over

=item tied(%SHASH)

Returns the handle via which I<%SHASH> is bound to the shared hash.
This is a shared hash handle that can be used by calling the methods
described above or by passing it to the functions of L<Hash::SharedMem>.

=item exists($SHASH{KEY})

Returns a truth value indicating whether the specified key is currently
present in the shared hash.

=item $SHASH{KEY}

Returns the value currently referenced by the specified key in the shared
hash, or C<undef> if the key is absent.

=item $SHASH{KEY} = NEWVALUE

Modifies the shared hash so that the specified key henceforth references
the specified value.  The new value must be a string.

=item delete($SHASH{KEY})

Modifies the shared hash so that the specified key is henceforth absent,
and returns the value that the key previously referenced, or C<undef>
if the key was already absent.  This swap is performed atomically.

=item %SHASH = LIST

Setting the entire content of the shared hash (throwing away the previous
content) is not supported.

=item each(%SHASH)

=item keys(%SHASH)

=item values(%SHASH)

=item %SHASH

Iteration over, or enumeration of, the shared hash's content is not
supported.

=item scalar(%SHASH)

Checking whether the shared hash is occupied is not supported.

=back

=head1 BUGS

Due to details of the Perl implementation, this object-oriented interface
to the shared hash mechanism is somewhat slower than the function
interface, and the tied interface is much slower.  The functions in
L<Hash::SharedMem> are the recommended interface.

=head1 SEE ALSO

L<Hash::SharedMem>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2014 PhotoBox Ltd

Copyright (C) 2014 Andrew Main (Zefram) <zefram@fysh.org>

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
