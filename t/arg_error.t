use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Scalar::String 0.000 qw(sclstr_downgraded sclstr_upgraded);
use Test::More tests => 446;

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
	sclstr_downgraded("foo"),
	sclstr_upgraded("foo"),
	sclstr_downgraded("\x{e9}foo"),
	sclstr_upgraded("\x{e9}foo"),
	sclstr_upgraded("\x{2603}foo"),
	${qr/foo/},
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
require_ok "Hash::SharedMem::Handle";
my %sh;
tie %sh, "Hash::SharedMem::Handle", $sh;
ok is_shash(tied(%sh));

foreach(
	undef,
	sclstr_upgraded("\x{2603}foo"),
	${qr/foo/},
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
	like $@, qr/\Akey is not an octet string at /;
	eval { shash_get($sh, $_) };
	like $@, qr/\Akey is not an octet string at /;
	eval { shash_set($sh, $_, "y") };
	like $@, qr/\Akey is not an octet string at /;
	eval { shash_gset($sh, $_, "y") };
	like $@, qr/\Akey is not an octet string at /;
	eval { shash_cset($sh, $_, "y", "z") };
	like $@, qr/\Akey is not an octet string at /;
	SKIP: {
		skip "copying mangles regexps on this Perl", 4
			if "$]" >= 5.011000 && "$]" < 5.011002 &&
			ref(\$_) eq "Regexp";
		no warnings "uninitialized";
		eval { my $e = exists $sh{$_} };
		like $@, qr/\Akey is not an octet string at /;
		eval { my $v = $sh{$_} };
		like $@, qr/\Akey is not an octet string at /;
		eval { $sh{$_} = "y" };
		like $@, qr/\Akey is not an octet string at /;
		eval { delete $sh{$_} };
		like $@, qr/\Akey is not an octet string at /;
	}
}

foreach(
	sclstr_upgraded("\x{2603}foo"),
	defined(${qr/foo/}) ? ${qr/foo/} : \1,
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
	like $@, qr/\Anew value is neither an octet string nor undef at /;
	eval { shash_gset($sh, "x", $_) };
	like $@, qr/\Anew value is neither an octet string nor undef at /;
	eval { shash_cset($sh, "x", $_, "z") };
	like $@, qr/\Acheck value is neither an octet string nor undef at /;
	eval { shash_cset($sh, "x", "y", $_) };
	like $@, qr/\Anew value is neither an octet string nor undef at /;
}

foreach(
	# These tests for tied hash values must omit the glob and regexp
	# test values that were used above, because per [perl #121477]
	# such values get mangled by the tying infrastructure.
	undef,
	sclstr_upgraded("\x{2603}foo"),
	\1,
	[],
	{},
	sub{},
	qr/foo/,
	\*foo,
	bless({}),
) {
	eval { $sh{x} = $_ };
	like $@, qr/\Anew value is not an octet string at /;
}

my $i = 1;

foreach(
	undef,
	${qr/foo/},
	*foo,
	\1,
	[],
	{},
	sub{},
	qr/foo/,
	\*foo,
	bless({}),
) {
	is eval { shash_open($_, "r") }, undef;
	like $@, qr/\Afilename is not a string at /;
	is eval { shash_open("$tmpdir/t".$i++, $_) }, undef;
	like $@, qr/\Amode is not a string at /;
	is eval { Hash::SharedMem::Handle->open($_, "r") }, undef;
	like $@, qr/\Afilename is not a string at /;
	is eval { Hash::SharedMem::Handle->open("$tmpdir/t".$i++, $_) }, undef;
	like $@, qr/\Amode is not a string at /;
	my %h;
	eval { tie %h, "Hash::SharedMem::Handle", $_, "r" };
	like $@, qr/\Afilename is not a string at /;
	eval { tie %h, "Hash::SharedMem::Handle", "$tmpdir/t".$i++, $_ };
	like $@, qr/\Amode is not a string at /;
}

1;
