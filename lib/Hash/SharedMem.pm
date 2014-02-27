=head1 NAME

Hash::SharedMem - efficient shared mutable hash

=head1 SYNOPSIS

	use Hash::SharedMem qw(is_shash check_shash);

	if(is_shash($arg)) { ...
	check_shash($arg);

	use Hash::SharedMem qw(shash_open);

	$shash = shash_open($filename, "rwc");

	use Hash::SharedMem
		qw(shash_is_readable shash_is_writable shash_mode);

	if(shash_is_readable($shash)) { ...
	if(shash_is_writable($shash)) { ...
	$mode = shash_mode($shash);

	use Hash::SharedMem qw(
		shash_getd shash_get shash_set shash_gset shash_cset
	);

	if(shash_getd($shash, $key)) { ...
	$value = shash_get($shash, $key);
	shash_set($shash, $key, $newvalue);
	$oldvalue = shash_gset($shash, $key, $newvalue);
	if(shash_cset($shash, $key, $chkvalue, $newvalue)) { ...

	use Hash::SharedMem qw(shash_snapshot shash_is_snapshot);

	$snap_shash = shash_snapshot($shash);
	if(shash_is_snapshot($shash)) { ...

=head1 DESCRIPTION

This module provides a facility for efficiently sharing mutable data
between processes on one host.  Data is organised as a key/value store,
resembling a Perl hash.  The keys and values are restricted to octet
(Latin-1) strings.

The data is represented in files that are mapped into each process's
memory space, which for interprocess communication amounts to the
processes sharing memory.  Processes are never blocked waiting for each
other.  The use of files means that there is some persistence, with the
data continuing to exist when there are no processes with it mapped.

=head2 Consistency and synchronisation

A shared hash is held in regular files, grouped in a directory.  At all
times, the OS-visible state of the files provides a consistent view of the
hash's content, from which read and write operations can proceed.  It is
no problem for a process using the shared hash to crash; other processes,
running concurrently or later, will be unimpeded in using the shared hash.

It is mainly intended that the shared hash should be held on a
memory-backed filesystem, and will therefore only last as long as the
machine stays up.  However, it can use any filesystem that supports
L<mmap(2)>, including conventional disk filesystems such as ext2.
In this case, as long as the OS shuts down cleanly (synching all file
writes to the underlying disk), a consistent state of the shared hash
will persist between boots, and usage of the shared hash can continue
after the OS boots again.  Note that only the OS is required to shut
down cleanly; it still doesn't matter if user processes crash.

Because the OS is likely to reorder file writes when writing them to disk,
the instantaneous state of the shared hash's files on disk is generally
I<not> guaranteed to be consistent.  So if the OS crashes, upon reboot
the files are liable to be in an inconsistent state (corrupted).

Maintaining consistency across an OS crash is a feature likely to be
added to this module in the future.  Durability of writes, for which
that is a prerequisite, is another likely future addition.

=cut

package Hash::SharedMem;

{ use 5.014; }
use warnings;
use strict;

our $VERSION = "0.000";

use parent "Exporter";
our @EXPORT_OK = qw(
	is_shash check_shash
	shash_open
	shash_is_readable shash_is_writable shash_mode
	shash_getd shash_get shash_set shash_gset shash_cset
	shash_snapshot shash_is_snapshot
);

require XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

=head1 FUNCTIONS

The I<SHASH> parameter that most of these functions take must be a handle
referring to a shared hash object.

=head2 Classification

=over

=item is_shash(ARG)

Returns a truth value indicating whether I<ARG> is a handle referring
to a shared hash object.

=item check_shash(ARG)

Checks whether I<ARG> is a handle referring to a shared hash object.
Returns normally if it is, or C<die>s if it is not.

=back

=head2 Opening

=over

=item shash_open(FILENAME, MODE)

Opens and return a handle referring to a shared hash object, or C<die>s
if the shared hash can't be opened as specified.  I<FILENAME> must
refer to the directory that encapsulates the shared hash.  I<MODE> is
a string controlling how the shared hash will be used.  It can contain
these characters:

=over

=item B<r>

The shared hash is to be readable.  If this is not specified then
read operations through the handle will be denied.  Beware that at the
system-call level the files are necessarily opened readably.  Thus read
permission on the files is required even if one will only be writing.

=item B<w>

The shared hash is to be writable.  If this is not specified then write
operations through the handle will be denied.  This flag also determines
how the files are opened at the system-call level, so write permission
on the files operates as expected.

=item B<c>

The shared hash will be created if it does not already exist.  If this
is not specified then the shared hash must already exist.

=item B<e>

The shared hash must not already exist.  If this is not specified and the
shared hash already exists then it will be opened normally.  This flag
is meant to be used with B<c>; it means that a successful open implies
that this process, rather than any other, is the one that created the
shared hash.

=back

When a shared hash is created, some of its constituent files will
be opened in read/write mode even if read-only mode was requested.
Store creation is not an atomic process, so if a creation attempt is
interrupted it may leave a half-created shared hash behind.  This does
not prevent a subsequent creation attempt on the same shared hash from
succeeding: creation will continue from whatever stage it had reached.
Likewise, multiple simultaneous creation attempts may each do part of the
job.  This can result in ownerships and permissions being inconsistent;
it is necessary that all creators (and all writers) use compatible
permission settings.

Regardless of the combination of efforts leading to the creation of a
shared hash, completion of the process is atomic.  Non-creating open
attempts will either report that there is no shared hash or open the
created shared hash.  Exactly one creation attempt will be judged to have
created the shared hash, and this is detectable through the B<e> flag.

=back

=head2 Mode checking

=over

=item shash_is_readable(SHASH)

Returns a truth value indicating whether the shared hash can be read
from through this handle.

=item shash_is_writable(SHASH)

Returns a truth value indicating whether the shared hash can be written
to through this handle.

=item shash_mode(SHASH)

Returns a string in which characters indicate the mode of this handle.
It matches the form of the I<MODE> parameter to L</shash_open>, but
mode flags that are only relevant during the opening process (B<c>
and B<e>) are not included.  The returned string can therefore contain
these characters:

=over

=item B<r>

The shared hash can be read from through this handle.

=item B<w>

The shared hash can be written to through this handle.

=back

=back

=head2 Data operations

For all of these functions, the key of interest (I<KEY> parameter)
can be any octet (Latin-1) string, and values (I<VALUE> parameters and
some return values) can be any octet string or C<undef>.  The C<undef>
value represents the absence of a key from the hash; there is no
present-but-undefined state.  Non-octets (Unicode characters above U+FF)
cannot be included in shared hashes, and items other than strings cannot
be used as keys or values.  If a dualvar (scalar with independent string
and numeric values) is supplied, only its string value will be used.

=over

=item shash_getd(SHASH, KEY)

Returns a truth value indicating whether the specified key currently
references a defined value in the shared hash.

=item shash_get(SHASH, KEY)

Returns the value currently referenced by the specified key in the
shared hash.

=item shash_set(SHASH, KEY, NEWVALUE)

Modifies the shared hash so that the specified key henceforth references
the specified value.

=item shash_gset(SHASH, KEY, NEWVALUE)

Modifies the shared hash so that the specified key henceforth references
the value I<NEWVALUE>, and returns the value that the key previously
referenced.  This swap is performed atomically.

=item shash_cset(SHASH, KEY, CHKVALUE, NEWVALUE)

Examines the value currently referenced by the specified key in the
shared hash.  If it is identical to I<CHKVALUE>, the function modifies
the shared hash so that the specified key henceforth references the value
I<NEWVALUE>, and returns true.  If the current value is not identical
to I<CHKVALUE>, the function leaves it unmodified and returns false.
This conditional modification is performed atomically.

This function can be used as a core on which to build arbitrarily
complex kinds of atomic operation (on a single key).  For example,
an atomic increment can be implemented as

	do {
		$ov = shash_get($shash, $key);
		$nv = $ov + 1;
	} until shash_cset($shash, $key, $ov, $nv);

=back

=head2 Snapshots

=over

=item shash_snapshot(SHASH)

Returns a shared hash handle that encapsulates the current contents of the
shared hash.  The entire state of the shared hash is captured atomically,
and the returned handle can be used to perform arbitrarily many read
operations on that state: it will never reflect later modifications to
the shared hash.  The snapshot handle cannot be used for writing.

=item shash_is_snapshot(SHASH)

Returns a truth value indicating whether this handle refers to a snapshot
(as opposed to a live shared hash).

=back

=head1 BUGS

As explained for L</shash_open>, creation of a shared hash is not atomic.
This is an unavoidable consequence of the need for the shared hash to
consist of multiple files in a directory.  Not only multi-party creation
but also normal operation of a shared hash can result in the files having
different ownerships and permissions.  All writers of a shared hash must
use compatible permission settings.

This module requires that the OS, C compiler, and Perl each provide
some fairly modern facilities.  For example, the OS must supply the
L<openat(2)> family of system calls.  Portability is therefore weaker than
usual for Perl modules of this general nature.  Some of the portability
issues are likely to be resolved in a future version.

Some parameters of the shared hash format that should vary according to
CPU architecture currently have fixed values, appropriate for IA32/AMD64.
On other architectures this module is liable to fail entirely or to
suffer performance problems.  This will be improved in a future version.

=head1 SEE ALSO

L<Hash::SharedMem::Handle>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2014 PhotoBox Ltd

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
