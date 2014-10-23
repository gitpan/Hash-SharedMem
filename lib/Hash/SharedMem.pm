=head1 NAME

Hash::SharedMem - efficient shared mutable hash

=head1 SYNOPSIS

	use Hash::SharedMem qw(shash_referential_handle);

	if(shash_referential_handle) { ...

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

	use Hash::SharedMem qw(shash_idle shash_tidy);

	shash_idle($shash);
	shash_tidy($shash);

	use Hash::SharedMem qw(
		shash_tally_get shash_tally_zero shash_tally_gzero
	);

	$tally = shash_tally_get($shash);
	shash_tally_zero($shash);
	$tally = shash_tally_gzero($shash);

=head1 DESCRIPTION

This module provides a facility for efficiently sharing mutable data
between processes on one host.  Data is organised as a key/value store,
resembling a Perl hash.  The keys and values are restricted to octet
(Latin-1) strings.  Structured objects may be stored by serialising them
using a mechanism such as L<Sereal>.

The data is represented in files that are mapped into each process's
memory space, which for interprocess communication amounts to the
processes sharing memory.  Processes are never blocked waiting for each
other.  The use of files means that there is some persistence, with the
data continuing to exist when there are no processes with it mapped.

The data structure is optimised for the case where all the data fits
into RAM.  This happens either via buffering of a disk-based filesystem,
or as the normal operation of a memory-backed filesystem, in either case
as long as there isn't much swapping activity.  If RAM isn't large enough,
such that the data has to reside mainly on disk and parts of it have to
be frequently reread from disk, speed will seriously suffer.  The data
structure exhibits poor locality of reference, and is not designed to
play nicely with filesystem block sizes.

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

=head2 File permissions

To read normally from a shared hash requires read and search (execute)
permission on the shared hash directory and read permission on all the
regular files in the directory.  To write normally requires read, write,
and search permissions on the directory and read and write permissions
on all the regular files.  For security purposes, some information about
shared hash content can be gleaned by anyone who has read or search
permission on the directory, and content can be modified by anyone who
has search permission on the directory and write permission on either
the directory or any of the regular files.

The file permission bits on a shared hash are determined by the
circumstances in which it was created, specifically by the umask in
effect at the point of creation.  As shared hash creation is unavoidably
non-atomic, competing creation attempts can cause trouble, and the
resulting permissions are only guaranteed if all competing attempts at
creation use the same umask.  After the shared hash is fully created,
subsequently opening it with the create flag set doesn't affect
permissions.

The directory gets permissions C<rwxrwxrwx> modified by the creation
umask, and the regular files in it get permissions C<rw-rw-rw-> modified
by the creation umask.  All the regular files that contain any part of
the shared hash content will get the same permission bits.  This includes
files created long after initial creation of the shared hash, which are
created as part of shared hash write operations; the umask in effect at
the point of those operations is insignificant.

File ownership and group assignment are not so controlled.  An attempt
is made to give all files the same group assignment and ownership,
determined by the creation of the shared hash, but the ability to do so
is limited by OS semantics.  Typically, users other than the superuser
cannot affect ownership, and can only assign files to groups of which
they are members.  Also, as with permission bits, competing creation
attempts can make ownerships and group assignments inconsistent, even
if they are generally controllable.

Where they can't be freely set, each regular file gets whatever ownership
and group assignment arise naturally from the circumstances in which it
was created.  If multiple users write to a single shared hash, it is to be
expected that the constituent files will end up having different owners.
It is up to the user to ensure that the varying ownerships combined
with the consistent permission bits yield compatible permissions for all
intended users of the shared hash.  Group-based permissions should work
provided that all writers are members of the relevant group.

=head2 Filesystem referential integrity

If the system calls L<openat(2)> et al are supported by the kernel
and the C library, then an open shared hash handle contains an
OS-supported first-class reference to the shared hash to which it refers.
(Specifically, it has a file descriptor referring to the shared hash
directory.)  In this situation, the reference remains valid regardless of
filename changes.  The shared hash can be renamed or moved arbitrarily,
within the filesystem, or the process can change its current directory
or root directory, and the handle remains valid.

If these modern system calls are not available, then an open shared
hash handle cannot contain a first-class reference to the shared hash
directory.  Instead it must repeatedly refer to the directory by name.
The name supplied to L</shash_open> is resolved to an absolute pathname,
so the handle will continue to work if the process changes its current
directory.  But any renaming of the shared hash, or the process changing
its root directory, will cause the handle to fail at the next operation
that requires the use of filenames.  (This is unlikely to be the very
next operation after the pathname becomes invalid.)  An attempt is made to
ensure that the stored pathname is still correct each time it is used, but
there is unavoidably a race condition, whereby some very unluckily timed
renaming could cause an operation to be applied to the wrong directory.

The means by which shared hash handles reference their directories is
indicated by the constant L</shash_referential_handle>.

When a shared hash is being opened, if it already exists then the name
passed to L</shash_open> is resolved just once to determine to what shared
hash it refers.  If the modern system calls are supported, this yields
perfectly clean name resolution semantics.  However, if a shared hash does
not already exist, its creation cannot currently be so perfectly clean.
The name passed to L</shash_open> must be resolved at least twice, once
to create the shared hash directory and once to acquire a reference to it
(of whichever type).  There is unavoidably a race condition here.

=head2 File operations

Because a shared hash is encapsulated in a directory, rather than being a
single non-directory file, the ability to perform file operations on it is
limited.  Although it can be renamed or moved, under POSIX semantics such
a rename can't atomically replace any file other than an empty directory.
In particular, it can't atomically replace another shared hash.  It also
can't be hard-linked to have multiple names.  (However, a major use
case for L<link(2)>, non-overwriting renaming, can be achieved through
L<rename(2)> due to the latter's limitations for directories.)  Finally,
it can't be unlinked.  (Linking and unlinking directories are possible for
root on some systems, but cause undesirable filesystem irregularities.)

A shared hash can be disposed of by applying C<rm -r> to its directory.
This is not equivalent to L<unlink(2)> (C<rm>) on a regular file,
because it not only removes the object's name but also disrupts its
internal structure.  If a process has an open handle referring to the
shared hash at the time of C<rm -r>, the use of the shared hash through
that handle is likely to fail, although probably not immediately.  If a
process is writing to the shared hash at the time of C<rm -r>, there is a
race condition that could prevent the removal from completing.  C<rm -r>
should therefore only be applied after all processes have finished using
the shared hash.

A shared hash can be copied by means of C<cp -r> (not mere C<cp>), C<tar>,
or similar means.  It is safe to do this while processes have open handles
referring to the shared hash, and while processes are reading from it.
However, as with most forms of database file, if a process is writing to
the shared hash then the file copier is liable to pick up an inconsistent
(corrupted) view of the shared hash.  Copying should therefore only
be attempted at a time when no write operations are being performed.
It is acceptable for processes to have the shared hash open in write
mode, provided that they do not actually perform any write operation
while the copy is being made.

A file-level copying operation applied to a shared hash is likely to
result in a copy that occupies much more filesystem space than the
original.  This occurs because most of the time a large part of the
main data file is a filesystem hole, not occupying any actual storage.
Some copying mechanisms (such as GNU C<cp>) can recognise this and avoid
allocating unnecessary storage for the copy, but others (such as GNU
C<tar>) will blindly fill space with a lot of zeroes.  If the copy is
subsequently used in shared hash write operations, ultimately it will
recover from this inefficient block allocation.

=head2 Forking

If a process is duplicated by L<fork(2)> while it holds a shared hash
handle, the handle is duplicated with the rest of the process, so
both resulting processes have handles referring to the same underlying
shared hash.  Provided that the duplication did not happen during a shared
hash operation, both processes' handles will subsequently work normally,
and can be used independently.

Things are more difficult if a L<fork(2)> happens while a shared hash
operation is in progress.  This should not normally be possible to
achieve from Perl code: arbitrary Perl code should not run during the
critical part of an operation.  If a shared hash operator is given a
tied variable as a parameter, the magic method call for access to that
parameter occurs before the critical part, so a L<fork|perlfunc/fork>
in that method is safe.  If a signal is received during a shared hash
operation, any signal handler installed in L<%SIG|perlvar/%SIG> will
be deferred until the operation is complete, so a L<fork|perlfunc/fork>
in such a signal handler is also safe.  A problematic L<fork(2)> should
only be achievable by XS code.

If a L<fork(2)> does happen during the critical part of a shared hash
operation, the two resulting handles are liable to interfere if the
operation is resumed in both processes.  In this case, it is safe for at
most one process (which may be either of them) to resume the operation.
The other process must neither resume the operation in progress nor make
any further use of the handle.  It is safe for the non-resuming process
to chain a new program with L<execve(2)>, to terminate with L<_exit(2)>,
or generally to make use of the C library before doing either of those.
Attempting to run Perl code would be unwise.

On platforms lacking a native L<fork(2)>, the Perl function
L<fork|perlfunc/fork> actually creates a Perl L<thread|threads>.  In that
case the behaviour should be similar to that seen with a real L<fork(2)>,
as described in the next section.

=head2 Threads

This module can be used in multiple Perl L<threads> simultaneously.
The module may be loaded by multiple threads separately, or from
Perl 5.8.9 onwards may be loaded by a thread that spawns new threads.
(Prior to Perl 5.8.9, limitations of the threading system mean that
module data can't be correctly cloned upon thread spawning.  Any but
the most trivial cases of thread spawning with this module loaded will
crash the interpreter.  The rest of this section only applies to Perls
that fully support cloning.)

If a thread is spawned while the parent thread has an open shared hash
handle, the handle is duplicated, so that both resulting threads have
handles referring to the same underlying shared hash.  Provided that the
duplication did not happen during a shared hash operation, both threads'
handles will subsequently work normally, and can be used independently.

=head2 Tainting

If L<taint mode|perlsec/"Taint mode"> is enabled, taintedness is relevant
to some operations on shared hashes.  Shared hash handles mostly behave
like regular file handles for tainting purposes.  Where the following
description says that a result is "not tainted", that means it does
not get the taint flag set merely by virtue of the operation performed;
it may still be marked as tainted if other tainted data is part of the
same expression, due to Perl's conservative taint tracking.

The classification functions are happy to operate on tainted arguments.
Their results are not tainted.

When opening a shared hash, if the shared hash filename or the mode
string is tainted then it is not permitted to open for writing or with
the possibility of creating.  It is permitted to open non-creatingly for
reading regardless of taint status.  Of course, any kind of opening is
permitted in an untainted expression.

A shared hash handle per se is never tainted.

The results of the mode checking functions are not tainted.

It is permitted to write tainted data to a shared hash.  The data
operations all accept tainted arguments.  When reading from a shared hash,
the value referenced by any key existing in the hash is always tainted,
but an absent value is treated as clean.  So where a data operation
returns a value from the shared hash, the value will be tainted if it is
a string, but C<undef> representing an absent value will not be tainted.
The truth values returned by some operations are not tainted, even if
they are derived entirely from tainted data.

=cut

package Hash::SharedMem;

{ use 5.006; }
use warnings;
use strict;

our $VERSION = "0.003";

use parent "Exporter";
our @EXPORT_OK = qw(
	shash_referential_handle
	is_shash check_shash
	shash_open
	shash_is_readable shash_is_writable shash_mode
	shash_getd shash_get shash_set shash_gset shash_cset
	shash_snapshot shash_is_snapshot
	shash_idle shash_tidy
	shash_tally_get shash_tally_zero shash_tally_gzero
);

eval { local $SIG{__DIE__};
	require Devel::CallChecker;
	Devel::CallChecker->VERSION(0.003);
};

require XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

sub _deparse_shash_unop {
	my($self, $op, $name) = @_;
	my @k;
	for(my $k = $op->first; !$k->isa("B::NULL"); $k = $k->sibling) {
		push @k, $k;
	}
	return __PACKAGE__."::".$name.
		"(".join(", ", map { $self->deparse($_, 6) } @k).")";
}

if("$]" >= 5.013007) {
	foreach my $name (@EXPORT_OK) {
		next if $name eq "shash_referential_handle";
		no strict "refs";
		*{"B::Deparse::pp_$name"} =
			sub { _deparse_shash_unop($_[0], $_[1], $name) };
	}
}

=head1 CONSTANTS

=over

=item shash_referential_handle

Truth value indicating whether each shared hash handle contains
a first-class reference to the shared hash to which it refers.
See L</Filesystem referential integrity> above for discussion of the
significance of this.

=back

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
refer to the directory that encapsulates the shared hash.

If the filename string contains non-ASCII characters, then the filename
actually used consists of the octets of the internal encoding of the
string, which does not necessarily match the ostensible characters of the
string.  This gives inconsistent behaviour for the same character sequence
represented in the two different ways that Perl uses internally.  This is
consistent with the treatment of filenames in Perl's built-in operators
such as L<open|perlfunc/open>; see L<perlunicode/"When Unicode Does
Not Happen">.  This may change in future versions of Perl (beyond 5.20).

I<MODE> is a string controlling how the shared hash will be used.
It can contain these characters:

=over

=item B<r>

The shared hash is to be readable.  If this is not specified then
read operations through the handle will be denied.  Beware that at the
system-call level the files are necessarily opened readably.  Thus read
permission on the files is required even if one will only be writing.

=item B<w>

The shared hash is to be writable.  If this is not specified then write
operations through the handle will be denied.  This flag also determines
in what mode the files are opened at the system-call level, so write
permission on the files operates as expected.

=item B<c>

The shared hash will be created if it does not already exist.  The
permission bits on the shared hash will be controlled by the creating
process's umask.  If this flag is not specified then the shared hash
must already exist.

=item B<e>

The shared hash must not already exist.  If this is not specified and the
shared hash already exists then it will be opened normally.  This flag
is meant to be used with B<c>; it means that a successful open implies
that this process, rather than any other, is the one that created the
shared hash.

=back

When a shared hash is created, some of its constituent files will
be opened in read/write mode even if read-only mode was requested.
Shared hash creation is not an atomic process, so if a creation attempt
is interrupted it may leave a half-created shared hash behind.  This does
not prevent a subsequent creation attempt on the same shared hash from
succeeding: creation will continue from whatever stage it had reached.
Likewise, multiple simultaneous creation attempts may each do part of the
job.  This can result in ownerships and permissions being inconsistent;
see L</File permissions> above.

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
present-but-undefined state.  Strings containing non-octets (Unicode
characters above U+FF) and items other than strings cannot be used as
keys or values.  If a dualvar (scalar with independent string and numeric
values) is supplied, only its string value will be used.

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

Returns a shared hash handle that encapsulates the current content of the
shared hash.  The entire state of the shared hash is captured atomically,
and the returned handle can be used to perform arbitrarily many read
operations on that state: it will never reflect later modifications to
the shared hash.  The snapshot handle cannot be used for writing.

=item shash_is_snapshot(SHASH)

Returns a truth value indicating whether this handle refers to a snapshot
(as opposed to a live shared hash).

=back

=head2 Maintenance

=over

=item shash_idle(SHASH)

Puts the shared hash handle into a state where it occupies less
resources, at the expense of making the next operation through the
handle more expensive.  This doesn't change the visible behaviour of the
handle, and doesn't affect the state of the shared hash itself at all.
The invisible operations performed by this function may vary between
versions of this module.

This function should be called when the handle is going to be unused for
a lengthy period.  For example, if a long-running daemon uses a shared
hash in brief bursts once an hour, it should idle its handle at the end
of each burst of activity.

Currently the effect of this operation is to discard the handle's
memory mapping of the shared hash data file.  The next operation has to
reestablish the mapping.  The benefit of discarding the mapping is that
periodically the data file has to be replaced with a new one, but the
old data file continues to exist as long as some process has it mapped.
A process that is actively using the shared hash will quickly notice that
the data file has been replaced and will unmap the old one.  A process
with a handle that it's not using, however, could keep the old data
file in existence, occupying storage, long after it has no further use.
A handle that has been put into the idle state won't perpetuate the
existence of an obsolete data file.

=item shash_tidy(SHASH)

Rearranges the storage of the shared hash if it seems useful to do
so, to avoid tidying work having to be performed by other processes.
This doesn't change the visible content of the shared hash, but the
handle must be open for writing.  The invisible operations performed by
this function may vary between versions of this module.

This function should be called in circumstances where it is acceptable
to incur some delay for this maintenance work to complete.  For example,
it could be called periodically by a cron job.  Essentially, calling this
function signals that this is a convenient time at which (and process
in which) to perform maintenance.

If this maintenance work is not carried out by means of this function,
then ultimately it will be performed anyway, but less predictably and
possibly less conveniently.  Eventually it will become necessary to
perform maintenance in order to continue using the shared hash, at which
point the next process that attempts to write to it will carry out the
work and incur the cost.  The shared hash will still work properly in
that case, but the unlucky writer will experience a disproportionately
large delay in the completion of its write operation.  This could well
be a problem if the shared hash is large.

=back

=head2 Event counters

=over

=item shash_tally_get(SHASH)

Returns a reference to a hash of counts of events that have occurred with
this shared hash handle.  These counts may be of interest for profiling
and debugging purposes, but should not be relied upon for semantic
purposes.  The event types may vary between versions of this module.
Few of the event types make sense in terms of the API supplied by this
module: most of them are internal implementation details.

Events are counted separately for each handle.  The events counted are
associated specifically with the handle, rather than with the shared hash
as a whole.  Generally, an idle handle will accumulate no events, even
if the shared hash to which it refers is active.  The event counters
start at zero when a handle is opened, and can be reset to zero by
L</shash_tally_zero> or L</shash_tally_gzero>.

In the returned hash, each key identifies a type of event, and the
corresponding value is (unless wrapped) the number of times events of that
type have occurred on the handle since the counters were last zeroed.
Currently the event counters are held in fixed-size variables and can
wrap, so if event counts might get as high as 2^64 then they can't be
relied upon to be accurate.  Wrapping will not occur at less than 2^64;
in other respects, wrapping behaviour may change in the future.

The event types that are currently counted are:

=over

=item B<string_read>

Parse an octet string representation in a shared hash data file.

=item B<string_write>

Write an octet string representation into a shared hash data file.

=item B<bnode_read>

Parse a B-tree node representation in a shared hash data file.

=item B<bnode_write>

Write a B-tree node representation into a shared hash data file.

=item B<key_compare>

Compare two strings as shared hash keys.

=item B<root_change_attempt>

Attempt to replace the root pointer in a shared hash data file.  This may
be done to change the content of the shared hash, or as part of the
process of switching to a new data file.

=item B<root_change_success>

Succeed in replacing the root pointer in a shared hash data file.
An attempt will fail if another process changed the root pointer during
the operation that required this process to change the root pointer.

=item B<file_change_attempt>

Attempt to replace the data file in a shared hash.  This is necessary
from time to time as data files fill up.

=item B<file_change_success>

Succeed in replacing the data file in a shared hash.  An attempt will
fail if another process replaced the data file while this process was
initialising its new one.

=item B<data_read_op>

Perform a high-level data operation that purely reads from the shared
hash: L</shash_getd> or L</shash_get>.

=item B<data_write_op>

Perform a high-level data operation that writes, or at least may write,
to the shared hash: L</shash_set>, L</shash_gset>, or L</shash_cset>.

=back

=item shash_tally_zero(SHASH)

Zero the event counters that can be read by L</shash_tally_get>.

=item shash_tally_gzero(SHASH)

Zero the event counters that can be read by L</shash_tally_get>, and
return the values the event counters previously had, in the same form
as L</shash_tally_get>.  This swap is performed atomically.

=back

=head1 BUGS

As explained for L</shash_open>, creation of a shared hash is not atomic.
This is an unavoidable consequence of the need for the shared hash to
consist of multiple files in a directory.  Multi-party creation can result
in the files having different permission bits; to avoid this, all creators
should use the same umask.  Multiple users writing to a shared hash can
result in the files having different ownerships, so the permission bits
must be chosen to work appropriately with the chimeric ownership.

When calls to the functions supplied by this module are compiled down to
custom ops (which is attempted for performance reasons), the ability to
deparse the resulting code with L<B::Deparse> is limited.  Prior to Perl
5.13.7, deparsing will generate very incorrect code.  From Perl 5.13.7
onwards, deparsing should normally work, but will break if another module
defines a separate type of custom op that happens to have the same short
name (though these ops do not clash in other respects).

=head1 SEE ALSO

L<Hash::SharedMem::Handle>,
L<Sereal>

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
