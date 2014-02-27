use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 234;

BEGIN { use_ok "Hash::SharedMem", qw(
	is_shash check_shash
	shash_open
	shash_is_readable shash_is_writable shash_mode
	shash_getd shash_get shash_set shash_gset shash_cset
	shash_snapshot shash_is_snapshot
); }

foreach(
	undef,
	1,
	"foo",
	eval { ${qr/foo/} },
	*foo,
	\1,
	[],
	{},
	sub{},
	qr/foo/,
	\*foo,
	bless({}),
) {
	ok !is_shash($_);
	eval { check_shash($_) };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_is_readable($_) };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_is_writable($_) };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_mode($_) };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_getd($_, "x") };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_get($_, "x") };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_set($_, "x", "y") };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_gset($_, "x", "y") };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_cset($_, "x", "y", "z") };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_snapshot($_) };
	like $@, qr/\Ahandle is not a shared hash handle /;
	eval { shash_is_snapshot($_) };
	like $@, qr/\Ahandle is not a shared hash handle /;
}

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = shash_open("$tmpdir/t0", "rwc");
ok $sh;
ok is_shash($sh);
eval { check_shash($sh) };
is $@, "";

foreach(
	undef,
	eval { ${qr/foo/} },
	*foo,
	\1,
	[],
	{},
	sub{},
	qr/foo/,
	\*foo,
	bless({}),
) {
	eval { shash_getd($sh, $_) };
	like $@, qr/\Akey is not a string at /;
	eval { shash_get($sh, $_) };
	like $@, qr/\Akey is not a string at /;
	eval { shash_set($sh, $_, "y") };
	like $@, qr/\Akey is not a string at /;
	eval { shash_gset($sh, $_, "y") };
	like $@, qr/\Akey is not a string at /;
	eval { shash_cset($sh, $_, "y", "z") };
	like $@, qr/\Akey is not a string at /;
}

foreach(
	eval { ${qr/foo/} } // \1,
	*foo,
	\1,
	[],
	{},
	sub{},
	qr/foo/,
	\*foo,
	bless({}),
) {
	eval { shash_set($sh, "x", $_) };
	like $@, qr/\Anew value is neither a string nor undef at /;
	eval { shash_gset($sh, "x", $_) };
	like $@, qr/\Anew value is neither a string nor undef at /;
	eval { shash_cset($sh, "x", $_, "z") };
	like $@, qr/\Acheck value is neither a string nor undef at /;
	eval { shash_cset($sh, "x", "y", $_) };
	like $@, qr/\Anew value is neither a string nor undef at /;
}

1;
