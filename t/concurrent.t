use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 141;

BEGIN { use_ok "Hash::SharedMem", qw(
	is_shash shash_open
	shash_get shash_set shash_gset shash_cset
); }

my $tmpdir = tempdir(CLEANUP => 1);
my @sh;
$sh[0] = shash_open("$tmpdir/t0", "rwc");
ok $sh[0];
ok is_shash($sh[0]);
$sh[1] = shash_open("$tmpdir/t0", "rwc");
ok $sh[1];
ok is_shash($sh[1]);
$sh[2] = shash_open("$tmpdir/t0", "rw");
ok $sh[2];
ok is_shash($sh[2]);
$sh[3] = shash_open("$tmpdir/t0", "r");
ok $sh[3];
ok is_shash($sh[3]);

is shash_get($_, "a"), undef foreach @sh;
is shash_get($_, "b"), undef foreach @sh;
is shash_get($_, "c"), undef foreach @sh;
is shash_get($_, "d"), undef foreach @sh;
shash_set($sh[0], "a", "aa");
is shash_get($_, "a"), "aa" foreach @sh;
is shash_get($_, "b"), undef foreach @sh;
is shash_get($_, "c"), undef foreach @sh;
is shash_get($_, "d"), undef foreach @sh;
shash_set($sh[1], "b", "bb");
is shash_get($_, "a"), "aa" foreach @sh;
is shash_get($_, "b"), "bb" foreach @sh;
is shash_get($_, "c"), undef foreach @sh;
is shash_get($_, "d"), undef foreach @sh;
shash_set($sh[2], "c", "cc");
is shash_get($_, "a"), "aa" foreach @sh;
is shash_get($_, "b"), "bb" foreach @sh;
is shash_get($_, "c"), "cc" foreach @sh;
is shash_get($_, "d"), undef foreach @sh;
is shash_gset($sh[0], "a", "xx"), "aa";
is shash_get($_, "a"), "xx" foreach @sh;
is shash_get($_, "b"), "bb" foreach @sh;
is shash_get($_, "c"), "cc" foreach @sh;
is shash_get($_, "d"), undef foreach @sh;
is shash_gset($sh[1], "b", "yy"), "bb";
is shash_get($_, "a"), "xx" foreach @sh;
is shash_get($_, "b"), "yy" foreach @sh;
is shash_get($_, "c"), "cc" foreach @sh;
is shash_get($_, "d"), undef foreach @sh;
ok !shash_cset($sh[2], "c", "pp", "qq");
is shash_get($_, "a"), "xx" foreach @sh;
is shash_get($_, "b"), "yy" foreach @sh;
is shash_get($_, "c"), "cc" foreach @sh;
is shash_get($_, "d"), undef foreach @sh;
ok shash_cset($sh[2], "c", "cc", "zz");
is shash_get($_, "a"), "xx" foreach @sh;
is shash_get($_, "b"), "yy" foreach @sh;
is shash_get($_, "c"), "zz" foreach @sh;
is shash_get($_, "d"), undef foreach @sh;

1;
