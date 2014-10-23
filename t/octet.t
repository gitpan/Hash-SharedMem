use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Scalar::String 0.000 qw(
	sclstr_is_downgraded sclstr_is_upgraded
	sclstr_downgraded sclstr_upgraded
);
use Test::More tests => 544;

BEGIN { use_ok "Hash::SharedMem", qw(
	is_shash shash_open
	shash_getd shash_get shash_set shash_gset shash_cset
); }

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = shash_open("$tmpdir/t0", "rwc");
ok $sh;
ok is_shash($sh);

sub is_dg($$) {
	ok sclstr_is_downgraded($_[0]);
	is sclstr_downgraded($_[0]), sclstr_downgraded($_[1]);
}

shash_set($sh, sclstr_downgraded("a0foo"), "b0");
is shash_getd($sh, sclstr_downgraded("a0foo")), !!1;
is shash_getd($sh, sclstr_upgraded("a0foo")), !!1;
is_dg shash_get($sh, sclstr_downgraded("a0foo")), "b0";
is_dg shash_get($sh, sclstr_upgraded("a0foo")), "b0";
shash_set($sh, sclstr_upgraded("a1foo"), "b1");
is shash_getd($sh, sclstr_downgraded("a1foo")), !!1;
is shash_getd($sh, sclstr_upgraded("a1foo")), !!1;
is_dg shash_get($sh, sclstr_downgraded("a1foo")), "b1";
is_dg shash_get($sh, sclstr_upgraded("a1foo")), "b1";
shash_set($sh, sclstr_downgraded("a2\x{e9}foo"), "b2");
is shash_getd($sh, sclstr_downgraded("a2\x{e9}foo")), !!1;
is shash_getd($sh, sclstr_upgraded("a2\x{e9}foo")), !!1;
is_dg shash_get($sh, sclstr_downgraded("a2\x{e9}foo")), "b2";
is_dg shash_get($sh, sclstr_upgraded("a2\x{e9}foo")), "b2";
shash_set($sh, sclstr_upgraded("a3\x{e9}foo"), "b3");
is shash_getd($sh, sclstr_downgraded("a3\x{e9}foo")), !!1;
is shash_getd($sh, sclstr_upgraded("a3\x{e9}foo")), !!1;
is_dg shash_get($sh, sclstr_downgraded("a3\x{e9}foo")), "b3";
is_dg shash_get($sh, sclstr_upgraded("a3\x{e9}foo")), "b3";
eval { shash_set($sh, sclstr_upgraded("a4\x{2603}foo"), "b4") };
like $@, qr/\Akey is not an octet string at /;
is eval { shash_getd($sh, sclstr_upgraded("a4\x{2603}foo")) }, undef;
like $@, qr/\Akey is not an octet string at /;
is eval { shash_get($sh, sclstr_upgraded("a4\x{2603}foo")) }, undef;
like $@, qr/\Akey is not an octet string at /;

is shash_getd($sh, sclstr_downgraded("e0foo")), !!0;
is shash_getd($sh, sclstr_upgraded("e0foo")), !!0;
is shash_get($sh, sclstr_downgraded("e0foo")), undef;
is shash_get($sh, sclstr_upgraded("e0foo")), undef;
is shash_getd($sh, sclstr_downgraded("e1\x{e9}foo")), !!0;
is shash_getd($sh, sclstr_upgraded("e1\x{e9}foo")), !!0;
is shash_get($sh, sclstr_downgraded("e1\x{e9}foo")), undef;
is shash_get($sh, sclstr_upgraded("e1\x{e9}foo")), undef;
is eval { shash_getd($sh, sclstr_upgraded("e2\x{2603}foo")) }, undef;
like $@, qr/\Akey is not an octet string at /;
is eval { shash_get($sh, sclstr_upgraded("e2\x{2603}foo")) }, undef;
like $@, qr/\Akey is not an octet string at /;

shash_set($sh, "c0", sclstr_downgraded("d0foo"));
is_dg shash_get($sh, "c0"), "d0foo";
shash_set($sh, "c1", sclstr_upgraded("d1foo"));
is_dg shash_get($sh, "c1"), "d1foo";
shash_set($sh, "c2", sclstr_downgraded("d2\x{e9}foo"));
is_dg shash_get($sh, "c2"), "d2\x{e9}foo";
shash_set($sh, "c3", sclstr_upgraded("d3\x{e9}foo"));
is_dg shash_get($sh, "c3"), "d3\x{e9}foo";
eval { shash_set($sh, "c4", sclstr_upgraded("d4\x{2603}foo")) };
like $@, qr/\Anew value is neither an octet string nor undef at /;
is eval { shash_get($sh, "c4") }, undef;
is $@, "";

is shash_gset($sh, sclstr_downgraded("f0foo"), undef), undef;
is shash_get($sh, sclstr_downgraded("f0foo")), undef;
is shash_gset($sh, sclstr_downgraded("f0foo"), "g0a"), undef;
is_dg shash_get($sh, sclstr_downgraded("f0foo")), "g0a";
is_dg shash_gset($sh, sclstr_downgraded("f0foo"), "g0b"), "g0a";
is_dg shash_get($sh, sclstr_downgraded("f0foo")), "g0b";
is_dg shash_gset($sh, sclstr_downgraded("f0foo"), undef), "g0b";
is shash_get($sh, sclstr_downgraded("f0foo")), undef;
is shash_gset($sh, sclstr_upgraded("f1foo"), undef), undef;
is shash_get($sh, sclstr_downgraded("f1foo")), undef;
is shash_gset($sh, sclstr_upgraded("f1foo"), "g1a"), undef;
is_dg shash_get($sh, sclstr_downgraded("f1foo")), "g1a";
is_dg shash_gset($sh, sclstr_downgraded("f1foo"), "g1b"), "g1a";
is_dg shash_get($sh, sclstr_downgraded("f1foo")), "g1b";
is_dg shash_gset($sh, sclstr_upgraded("f1foo"), "g1c"), "g1b";
is_dg shash_get($sh, sclstr_downgraded("f1foo")), "g1c";
is_dg shash_gset($sh, sclstr_upgraded("f1foo"), "g1d"), "g1c";
is_dg shash_get($sh, sclstr_downgraded("f1foo")), "g1d";
is_dg shash_gset($sh, sclstr_upgraded("f1foo"), undef), "g1d";
is shash_gset($sh, sclstr_downgraded("f2\x{e9}foo"), undef), undef;
is shash_get($sh, sclstr_downgraded("f2\x{e9}foo")), undef;
is shash_gset($sh, sclstr_downgraded("f2\x{e9}foo"), "g2a"), undef;
is_dg shash_get($sh, sclstr_downgraded("f2\x{e9}foo")), "g2a";
is_dg shash_gset($sh, sclstr_downgraded("f2\x{e9}foo"), "g2b"), "g2a";
is_dg shash_get($sh, sclstr_downgraded("f2\x{e9}foo")), "g2b";
is_dg shash_gset($sh, sclstr_downgraded("f2\x{e9}foo"), undef), "g2b";
is shash_get($sh, sclstr_downgraded("f2\x{e9}foo")), undef;
is shash_gset($sh, sclstr_upgraded("f3\x{e9}foo"), undef), undef;
is shash_get($sh, sclstr_downgraded("f3\x{e9}foo")), undef;
is shash_gset($sh, sclstr_upgraded("f3\x{e9}foo"), "g3a"), undef;
is_dg shash_get($sh, sclstr_downgraded("f3\x{e9}foo")), "g3a";
is_dg shash_gset($sh, sclstr_downgraded("f3\x{e9}foo"), "g3b"), "g3a";
is_dg shash_get($sh, sclstr_downgraded("f3\x{e9}foo")), "g3b";
is_dg shash_gset($sh, sclstr_upgraded("f3\x{e9}foo"), "g3c"), "g3b";
is_dg shash_get($sh, sclstr_downgraded("f3\x{e9}foo")), "g3c";
is_dg shash_gset($sh, sclstr_upgraded("f3\x{e9}foo"), "g3d"), "g3c";
is_dg shash_get($sh, sclstr_downgraded("f3\x{e9}foo")), "g3d";
is_dg shash_gset($sh, sclstr_upgraded("f3\x{e9}foo"), undef), "g3d";
is eval { shash_gset($sh, sclstr_upgraded("f4\x{2603}foo"), undef) }, undef;
like $@, qr/\Akey is not an octet string at /;
is eval { shash_gset($sh, sclstr_upgraded("f4\x{2603}foo"), "g4a") }, undef;
like $@, qr/\Akey is not an octet string at /;

is shash_gset($sh, "h0", sclstr_downgraded("i0afoo")), undef;
is_dg shash_get($sh, "h0"), "i0afoo";
is_dg shash_gset($sh, "h0", sclstr_downgraded("i0bfoo")), "i0afoo";
is_dg shash_get($sh, "h0"), "i0bfoo";
is_dg shash_gset($sh, "h0", undef), "i0bfoo";
is shash_get($sh, "h0"), undef;
is shash_gset($sh, "h1", sclstr_upgraded("i1afoo")), undef;
is_dg shash_get($sh, "h1"), "i1afoo";
is_dg shash_gset($sh, "h1", sclstr_downgraded("i1bfoo")), "i1afoo";
is_dg shash_get($sh, "h1"), "i1bfoo";
is_dg shash_gset($sh, "h1", sclstr_upgraded("i1cfoo")), "i1bfoo";
is_dg shash_get($sh, "h1"), "i1cfoo";
is_dg shash_gset($sh, "h1", sclstr_upgraded("i1dfoo")), "i1cfoo";
is_dg shash_get($sh, "h1"), "i1dfoo";
is_dg shash_gset($sh, "h1", undef), "i1dfoo";
is shash_get($sh, "h1"), undef;
is shash_gset($sh, "h2", sclstr_downgraded("i2a\x{e9}foo")), undef;
is_dg shash_get($sh, "h2"), "i2a\x{e9}foo";
is_dg shash_gset($sh, "h2", sclstr_downgraded("i2b\x{e9}foo")), "i2a\x{e9}foo";
is_dg shash_get($sh, "h2"), "i2b\x{e9}foo";
is_dg shash_gset($sh, "h2", undef), "i2b\x{e9}foo";
is shash_get($sh, "h2"), undef;
is shash_gset($sh, "h3", sclstr_upgraded("i3a\x{e9}foo")), undef;
is_dg shash_get($sh, "h3"), "i3a\x{e9}foo";
is_dg shash_gset($sh, "h3", sclstr_downgraded("i3b\x{e9}foo")), "i3a\x{e9}foo";
is_dg shash_get($sh, "h3"), "i3b\x{e9}foo";
is_dg shash_gset($sh, "h3", sclstr_upgraded("i3c\x{e9}foo")), "i3b\x{e9}foo";
is_dg shash_get($sh, "h3"), "i3c\x{e9}foo";
is_dg shash_gset($sh, "h3", sclstr_upgraded("i3d\x{e9}foo")), "i3c\x{e9}foo";
is_dg shash_get($sh, "h3"), "i3d\x{e9}foo";
is_dg shash_gset($sh, "h3", undef), "i3d\x{e9}foo";
is shash_get($sh, "h3"), undef;
is eval { shash_gset($sh, "h4", sclstr_upgraded("i4a\x{2603}foo")) }, undef;
like $@, qr/\Anew value is neither an octet string nor undef at /;
is shash_get($sh, "h4"), undef;
is shash_gset($sh, "h4", "i4bfoo"), undef;
is eval { shash_gset($sh, "h4", sclstr_upgraded("i4c\x{2603}foo")) }, undef;
like $@, qr/\Anew value is neither an octet string nor undef at /;
is_dg shash_get($sh, "h4"), "i4bfoo";

is shash_cset($sh, sclstr_downgraded("j0foo"), undef, undef), !!1;
is shash_get($sh, sclstr_downgraded("j0foo")), undef;
is shash_cset($sh, sclstr_downgraded("j0foo"), "k0a", undef), !!0;
is shash_get($sh, sclstr_downgraded("j0foo")), undef;
is shash_cset($sh, sclstr_downgraded("j0foo"), "k0b", "k0c"), !!0;
is shash_get($sh, sclstr_downgraded("j0foo")), undef;
is shash_cset($sh, sclstr_downgraded("j0foo"), undef, "k0d"), !!1;
is_dg shash_get($sh, sclstr_downgraded("j0foo")), "k0d";
is shash_cset($sh, sclstr_downgraded("j0foo"), undef, undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("j0foo")), "k0d";
is shash_cset($sh, sclstr_downgraded("j0foo"), undef, "k0e"), !!0;
is_dg shash_get($sh, sclstr_downgraded("j0foo")), "k0d";
is shash_cset($sh, sclstr_downgraded("j0foo"), "k0f", undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("j0foo")), "k0d";
is shash_cset($sh, sclstr_downgraded("j0foo"), "k0f", "k0g"), !!0;
is_dg shash_get($sh, sclstr_downgraded("j0foo")), "k0d";
is shash_cset($sh, sclstr_downgraded("j0foo"), "k0d", "k0h"), !!1;
is_dg shash_get($sh, sclstr_downgraded("j0foo")), "k0h";
is shash_cset($sh, sclstr_downgraded("j0foo"), "k0h", undef), !!1;
is shash_get($sh, sclstr_downgraded("j0foo")), undef;
is shash_cset($sh, sclstr_upgraded("j1foo"), undef, undef), !!1;
is shash_get($sh, sclstr_downgraded("j1foo")), undef;
is shash_cset($sh, sclstr_upgraded("j1foo"), "k1a", undef), !!0;
is shash_get($sh, sclstr_downgraded("j1foo")), undef;
is shash_cset($sh, sclstr_upgraded("j1foo"), "k1b", "k1c"), !!0;
is shash_get($sh, sclstr_downgraded("j1foo")), undef;
is shash_cset($sh, sclstr_upgraded("j1foo"), undef, "k1d"), !!1;
is_dg shash_get($sh, sclstr_downgraded("j1foo")), "k1d";
is shash_cset($sh, sclstr_upgraded("j1foo"), undef, undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("j1foo")), "k1d";
is shash_cset($sh, sclstr_upgraded("j1foo"), undef, "k1e"), !!0;
is_dg shash_get($sh, sclstr_downgraded("j1foo")), "k1d";
is shash_cset($sh, sclstr_upgraded("j1foo"), "k1f", undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("j1foo")), "k1d";
is shash_cset($sh, sclstr_upgraded("j1foo"), "k1f", "k1g"), !!0;
is_dg shash_get($sh, sclstr_downgraded("j1foo")), "k1d";
is shash_cset($sh, sclstr_upgraded("j1foo"), "k1d", "k1h"), !!1;
is_dg shash_get($sh, sclstr_downgraded("j1foo")), "k1h";
is shash_cset($sh, sclstr_upgraded("j1foo"), "k1h", undef), !!1;
is shash_get($sh, sclstr_downgraded("j1foo")), undef;
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), undef, undef), !!1;
is shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), undef;
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), "k2a", undef), !!0;
is shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), undef;
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), "k2b", "k2c"), !!0;
is shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), undef;
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), undef, "k2d"), !!1;
is_dg shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), "k2d";
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), undef, undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), "k2d";
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), undef, "k2e"), !!0;
is_dg shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), "k2d";
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), "k2f", undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), "k2d";
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), "k2f", "k2g"), !!0;
is_dg shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), "k2d";
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), "k2d", "k2h"), !!1;
is_dg shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), "k2h";
is shash_cset($sh, sclstr_downgraded("j2\x{e9}foo"), "k2h", undef), !!1;
is shash_get($sh, sclstr_downgraded("j2\x{e9}foo")), undef;
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), undef, undef), !!1;
is shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), undef;
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), "k3a", undef), !!0;
is shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), undef;
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), "k3b", "k3c"), !!0;
is shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), undef;
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), undef, "k3d"), !!1;
is_dg shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), "k3d";
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), undef, undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), "k3d";
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), undef, "k3e"), !!0;
is_dg shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), "k3d";
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), "k3f", undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), "k3d";
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), "k3f", "k3g"), !!0;
is_dg shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), "k3d";
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), "k3d", "k3h"), !!1;
is_dg shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), "k3h";
is shash_cset($sh, sclstr_upgraded("j3\x{e9}foo"), "k3h", undef), !!1;
is shash_get($sh, sclstr_downgraded("j3\x{e9}foo")), undef;
is eval { shash_cset($sh, sclstr_upgraded("j4\x{2603}foo"), undef, undef) },
	undef;
like $@, qr/\Akey is not an octet string at /;
is eval { shash_cset($sh, sclstr_upgraded("j4\x{2603}foo"), "k4a", undef) },
	undef;
like $@, qr/\Akey is not an octet string at /;
is eval { shash_cset($sh, sclstr_upgraded("j4\x{2603}foo"), "k4b", "k4c") },
	undef;
like $@, qr/\Akey is not an octet string at /;
is eval { shash_cset($sh, sclstr_upgraded("j4\x{2603}foo"), undef, "k4d") },
	undef;
like $@, qr/\Akey is not an octet string at /;

is shash_cset($sh, "l0", undef, undef), !!1;
is shash_get($sh, "l0"), undef;
is shash_cset($sh, "l0", sclstr_downgraded("m0afoo"), undef), !!0;
is shash_get($sh, "l0"), undef;
is shash_cset($sh, "l0", sclstr_downgraded("m0bfoo"),
	sclstr_downgraded("m0cfoo")), !!0;
is shash_get($sh, "l0"), undef;
is shash_cset($sh, "l0", undef, sclstr_downgraded("m0dfoo")), !!1;
is_dg shash_get($sh, "l0"), "m0dfoo";
is shash_cset($sh, "l0", undef, undef), !!0;
is_dg shash_get($sh, "l0"), "m0dfoo";
is shash_cset($sh, "l0", undef, sclstr_downgraded("m0efoo")), !!0;
is_dg shash_get($sh, "l0"), "m0dfoo";
is shash_cset($sh, "l0", sclstr_downgraded("m0ffoo"), undef), !!0;
is_dg shash_get($sh, "l0"), "m0dfoo";
is shash_cset($sh, "l0", sclstr_downgraded("m0ffoo"),
	sclstr_downgraded("m0gfoo")), !!0;
is_dg shash_get($sh, "l0"), "m0dfoo";
is shash_cset($sh, "l0", sclstr_downgraded("m0dfoo"),
	sclstr_downgraded("m0hfoo")), !!1;
is_dg shash_get($sh, "l0"), "m0hfoo";
is shash_cset($sh, "l0", sclstr_downgraded("m0hfoo"), undef), !!1;
is shash_get($sh, "l0"), undef;
is shash_cset($sh, "l1", undef, undef), !!1;
is shash_get($sh, "l1"), undef;
is shash_cset($sh, "l1", sclstr_upgraded("m1afoo"), undef), !!0;
is shash_get($sh, "l1"), undef;
is shash_cset($sh, "l1", sclstr_upgraded("m1bfoo"),
	sclstr_upgraded("m1cfoo")), !!0;
is shash_get($sh, "l1"), undef;
is shash_cset($sh, "l1", undef, sclstr_upgraded("m1dfoo")), !!1;
is_dg shash_get($sh, "l1"), "m1dfoo";
is shash_cset($sh, "l1", undef, undef), !!0;
is_dg shash_get($sh, "l1"), "m1dfoo";
is shash_cset($sh, "l1", undef, sclstr_upgraded("m1efoo")), !!0;
is_dg shash_get($sh, "l1"), "m1dfoo";
is shash_cset($sh, "l1", sclstr_upgraded("m1ffoo"), undef), !!0;
is_dg shash_get($sh, "l1"), "m1dfoo";
is shash_cset($sh, "l1", sclstr_upgraded("m1ffoo"),
	sclstr_upgraded("m1gfoo")), !!0;
is_dg shash_get($sh, "l1"), "m1dfoo";
is shash_cset($sh, "l1", sclstr_upgraded("m1dfoo"),
	sclstr_upgraded("m1hfoo")), !!1;
is_dg shash_get($sh, "l1"), "m1hfoo";
is shash_cset($sh, "l1", sclstr_upgraded("m1hfoo"), undef), !!1;
is shash_get($sh, "l1"), undef;
is shash_cset($sh, "l2", undef, undef), !!1;
is shash_get($sh, "l2"), undef;
is shash_cset($sh, "l2", sclstr_downgraded("m2a\x{e9}foo"), undef), !!0;
is shash_get($sh, "l2"), undef;
is shash_cset($sh, "l2", sclstr_downgraded("m2b\x{e9}foo"),
	sclstr_downgraded("m2c\x{e9}foo")), !!0;
is shash_get($sh, "l2"), undef;
is shash_cset($sh, "l2", undef, sclstr_downgraded("m2d\x{e9}foo")), !!1;
is_dg shash_get($sh, "l2"), "m2d\x{e9}foo";
is shash_cset($sh, "l2", undef, undef), !!0;
is_dg shash_get($sh, "l2"), "m2d\x{e9}foo";
is shash_cset($sh, "l2", undef, sclstr_downgraded("m2e\x{e9}foo")), !!0;
is_dg shash_get($sh, "l2"), "m2d\x{e9}foo";
is shash_cset($sh, "l2", sclstr_downgraded("m2f\x{e9}foo"), undef), !!0;
is_dg shash_get($sh, "l2"), "m2d\x{e9}foo";
is shash_cset($sh, "l2", sclstr_downgraded("m2f\x{e9}foo"),
	sclstr_downgraded("m2g\x{e9}foo")), !!0;
is_dg shash_get($sh, "l2"), "m2d\x{e9}foo";
is shash_cset($sh, "l2", sclstr_downgraded("m2d\x{e9}foo"),
	sclstr_downgraded("m2h\x{e9}foo")), !!1;
is_dg shash_get($sh, "l2"), "m2h\x{e9}foo";
is shash_cset($sh, "l2", sclstr_downgraded("m2h\x{e9}foo"), undef), !!1;
is shash_get($sh, "l2"), undef;
is shash_cset($sh, "l3", undef, undef), !!1;
is shash_get($sh, "l3"), undef;
is shash_cset($sh, "l3", sclstr_upgraded("m3a\x{e9}foo"), undef), !!0;
is shash_get($sh, "l3"), undef;
is shash_cset($sh, "l3", sclstr_upgraded("m3b\x{e9}foo"),
	sclstr_upgraded("m3c\x{e9}foo")), !!0;
is shash_get($sh, "l3"), undef;
is shash_cset($sh, "l3", undef, sclstr_upgraded("m3d\x{e9}foo")), !!1;
is_dg shash_get($sh, "l3"), "m3d\x{e9}foo";
is shash_cset($sh, "l3", undef, undef), !!0;
is_dg shash_get($sh, "l3"), "m3d\x{e9}foo";
is shash_cset($sh, "l3", undef, sclstr_upgraded("m3e\x{e9}foo")), !!0;
is_dg shash_get($sh, "l3"), "m3d\x{e9}foo";
is shash_cset($sh, "l3", sclstr_upgraded("m3f\x{e9}foo"), undef), !!0;
is_dg shash_get($sh, "l3"), "m3d\x{e9}foo";
is shash_cset($sh, "l3", sclstr_upgraded("m3f\x{e9}foo"),
	sclstr_upgraded("m3g\x{e9}foo")), !!0;
is_dg shash_get($sh, "l3"), "m3d\x{e9}foo";
is shash_cset($sh, "l3", sclstr_upgraded("m3d\x{e9}foo"),
	sclstr_upgraded("m3h\x{e9}foo")), !!1;
is_dg shash_get($sh, "l3"), "m3h\x{e9}foo";
is shash_cset($sh, "l3", sclstr_upgraded("m3h\x{e9}foo"), undef), !!1;
is shash_get($sh, "l3"), undef;
is eval { shash_cset($sh, "l4", undef, sclstr_upgraded("m4a\x{2603}foo")) },
	undef;
like $@, qr/\Anew value is neither an octet string nor undef at /;
is shash_get($sh, "l4"), undef;
is eval { shash_cset($sh, "l4", "m4bfoo", sclstr_upgraded("m4c\x{2603}foo")) },
	undef;
like $@, qr/\Anew value is neither an octet string nor undef at /;
is shash_get($sh, "l4"), undef;
is shash_cset($sh, "l4", undef, "m4dfoo"), !!1;
is shash_get($sh, "l4"), "m4dfoo";
is eval { shash_cset($sh, "l4", undef, sclstr_upgraded("m4e\x{2603}foo")) },
	undef;
like $@, qr/\Anew value is neither an octet string nor undef at /;
is shash_get($sh, "l4"), "m4dfoo";
is eval { shash_cset($sh, "l4", "m4ffoo", sclstr_upgraded("m4g\x{2603}foo")) },
	undef;
like $@, qr/\Anew value is neither an octet string nor undef at /;
is shash_get($sh, "l4"), "m4dfoo";
is eval { shash_cset($sh, "l4", "m4dfoo", sclstr_upgraded("m4h\x{2603}foo")) },
	undef;
like $@, qr/\Anew value is neither an octet string nor undef at /;
is shash_get($sh, "l4"), "m4dfoo";

require_ok "Hash::SharedMem::Handle";
my %sh;
tie %sh, "Hash::SharedMem::Handle", $sh;
ok is_shash(tied(%sh));
ok tied(%sh) == $sh;

$sh{sclstr_downgraded("n0foo")} = "o0";
is exists($sh{sclstr_downgraded("n0foo")}), !!1;
is exists($sh{sclstr_upgraded("n0foo")}), !!1;
is_dg $sh{sclstr_downgraded("n0foo")}, "o0";
is_dg $sh{sclstr_upgraded("n0foo")}, "o0";
is_dg delete($sh{sclstr_downgraded("n0foo")}), "o0";
is shash_getd($sh, sclstr_downgraded("n0foo")), !!0;
is delete($sh{sclstr_downgraded("n0foo")}), undef;
is shash_getd($sh, sclstr_downgraded("n0foo")), !!0;
$sh{sclstr_upgraded("n1foo")} = "o1";
is exists($sh{sclstr_downgraded("n1foo")}), !!1;
is exists($sh{sclstr_upgraded("n1foo")}), !!1;
is_dg $sh{sclstr_downgraded("n1foo")}, "o1";
is_dg $sh{sclstr_upgraded("n1foo")}, "o1";
is_dg delete($sh{sclstr_upgraded("n1foo")}), "o1";
is shash_getd($sh, sclstr_downgraded("n1foo")), !!0;
is delete($sh{sclstr_upgraded("n1foo")}), undef;
is shash_getd($sh, sclstr_downgraded("n1foo")), !!0;
$sh{sclstr_downgraded("n2\x{e9}foo")} = "o2";
is exists($sh{sclstr_downgraded("n2\x{e9}foo")}), !!1;
is exists($sh{sclstr_upgraded("n2\x{e9}foo")}), !!1;
is_dg $sh{sclstr_downgraded("n2\x{e9}foo")}, "o2";
is_dg $sh{sclstr_upgraded("n2\x{e9}foo")}, "o2";
is_dg delete($sh{sclstr_downgraded("n2\x{e9}foo")}), "o2";
is shash_getd($sh, sclstr_downgraded("n2\x{e9}foo")), !!0;
is delete($sh{sclstr_downgraded("n2\x{e9}foo")}), undef;
is shash_getd($sh, sclstr_downgraded("n2\x{e9}foo")), !!0;
$sh{sclstr_upgraded("n3\x{e9}foo")} = "o3";
is exists($sh{sclstr_downgraded("n3\x{e9}foo")}), !!1;
is exists($sh{sclstr_upgraded("n3\x{e9}foo")}), !!1;
is_dg $sh{sclstr_downgraded("n3\x{e9}foo")}, "o3";
is_dg $sh{sclstr_upgraded("n3\x{e9}foo")}, "o3";
is_dg delete($sh{sclstr_upgraded("n3\x{e9}foo")}), "o3";
is shash_getd($sh, sclstr_downgraded("n3\x{e9}foo")), !!0;
is delete($sh{sclstr_upgraded("n3\x{e9}foo")}), undef;
is shash_getd($sh, sclstr_downgraded("n3\x{e9}foo")), !!0;
eval { $sh{sclstr_upgraded("n4\x{2603}foo")} = "o4" };
like $@, qr/\Akey is not an octet string at /;
is eval { delete($sh{sclstr_upgraded("n5\x{2603}foo")}) }, undef;
like $@, qr/\Akey is not an octet string at /;
is eval { exists($sh{sclstr_upgraded("n6\x{2603}foo")}) }, undef;
like $@, qr/\Akey is not an octet string at /;
is eval { $sh{sclstr_upgraded("n6\x{2603}foo")} }, undef;
like $@, qr/\Akey is not an octet string at /;

$sh{p0} = sclstr_downgraded("q0foo");
is_dg $sh{p0}, "q0foo";
$sh{p1} = sclstr_upgraded("q1foo");
is_dg $sh{p1}, "q1foo";
$sh{p2} = sclstr_downgraded("q2\x{e9}foo");
is_dg $sh{p2}, "q2\x{e9}foo";
$sh{p3} = sclstr_upgraded("q3\x{e9}foo");
is_dg $sh{p3}, "q3\x{e9}foo";
eval { $sh{p4} = sclstr_upgraded("q4\x{2603}foo") };
like $@, qr/\Anew value is not an octet string at /;
is eval { $sh{p4} }, undef;
is $@, "";

like $tmpdir, qr/\A[\x01-\x7f]+\z/;
my $fn;
use if "$]" < 5.008, "utf8";

$fn = sclstr_downgraded("$tmpdir/t1foo");
$sh = shash_open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t1foo/iNmv0,m\$%3");
ok sclstr_is_downgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t1foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t2foo");
$sh = shash_open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t2foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t2foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_downgraded("$tmpdir/t3\x{e9}foo");
$sh = shash_open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t3\x{e9}foo/iNmv0,m\$%3");
ok sclstr_is_downgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t3\x{e9}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t4\x{e9}foo");
$sh = shash_open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t4\x{c3}\x{a9}foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t4\x{e9}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t5\x{2603}foo");
$sh = shash_open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t5\x{e2}\x{98}\x{83}foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t5\x{2603}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;

$fn = sclstr_downgraded("$tmpdir/t6foo");
$sh = Hash::SharedMem::Handle->open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t6foo/iNmv0,m\$%3");
ok sclstr_is_downgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t6foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t7foo");
$sh = Hash::SharedMem::Handle->open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t7foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t7foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_downgraded("$tmpdir/t8\x{e9}foo");
$sh = Hash::SharedMem::Handle->open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t8\x{e9}foo/iNmv0,m\$%3");
ok sclstr_is_downgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t8\x{e9}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t9\x{e9}foo");
$sh = Hash::SharedMem::Handle->open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t9\x{c3}\x{a9}foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t9\x{e9}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t10\x{2603}foo");
$sh = Hash::SharedMem::Handle->open($fn, "wc");
ok -f sclstr_downgraded("$tmpdir/t10\x{e2}\x{98}\x{83}foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { shash_get($sh, "a0") }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t10\x{2603}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;

$fn = sclstr_downgraded("$tmpdir/t11foo");
tie %sh, "Hash::SharedMem::Handle", $fn, "wc";
ok -f sclstr_downgraded("$tmpdir/t11foo/iNmv0,m\$%3");
ok sclstr_is_downgraded($fn);
is eval { $sh{a0} }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t11foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t12foo");
tie %sh, "Hash::SharedMem::Handle", $fn, "wc";
ok -f sclstr_downgraded("$tmpdir/t12foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { $sh{a0} }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t12foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_downgraded("$tmpdir/t13\x{e9}foo");
tie %sh, "Hash::SharedMem::Handle", $fn, "wc";
ok -f sclstr_downgraded("$tmpdir/t13\x{e9}foo/iNmv0,m\$%3");
ok sclstr_is_downgraded($fn);
is eval { $sh{a0} }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t13\x{e9}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t14\x{e9}foo");
tie %sh, "Hash::SharedMem::Handle", $fn, "wc";
ok -f sclstr_downgraded("$tmpdir/t14\x{c3}\x{a9}foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { $sh{a0} }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t14\x{e9}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
$fn = sclstr_upgraded("$tmpdir/t15\x{2603}foo");
tie %sh, "Hash::SharedMem::Handle", $fn, "wc";
ok -f sclstr_downgraded("$tmpdir/t15\x{e2}\x{98}\x{83}foo/iNmv0,m\$%3");
ok sclstr_is_upgraded($fn);
is eval { $sh{a0} }, undef;
like sclstr_upgraded($@), qr#\Acan't\ read\ shared\ hash
	\ \Q$tmpdir\E/t15\x{2603}foo:
	\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;

1;
