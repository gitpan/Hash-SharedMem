use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Scalar::String 0.000
	qw(sclstr_is_downgraded sclstr_downgraded sclstr_upgraded);
use Test::More tests => 366;

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

is shash_getd($sh, sclstr_downgraded("")), !!0;
is shash_getd($sh, sclstr_upgraded("")), !!0;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_get($sh, sclstr_upgraded("")), undef;
shash_set($sh, sclstr_downgraded(""), "b0");
shash_set($sh, sclstr_downgraded("a1"), "b1");
is shash_getd($sh, sclstr_downgraded("")), !!1;
is shash_getd($sh, sclstr_upgraded("")), !!1;
is_dg shash_get($sh, sclstr_downgraded("")), "b0";
is_dg shash_get($sh, sclstr_upgraded("")), "b0";
is shash_getd($sh, sclstr_downgraded("a1")), !!1;
is shash_getd($sh, sclstr_upgraded("a1")), !!1;
is_dg shash_get($sh, sclstr_downgraded("a1")), "b1";
is_dg shash_get($sh, sclstr_upgraded("a1")), "b1";
shash_set($sh, sclstr_downgraded(""), undef);
is shash_getd($sh, sclstr_downgraded("")), !!0;
is shash_getd($sh, sclstr_upgraded("")), !!0;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_get($sh, sclstr_upgraded("")), undef;
shash_set($sh, sclstr_upgraded(""), "b2");
shash_set($sh, sclstr_upgraded("a3"), "b3");
is shash_getd($sh, sclstr_downgraded("")), !!1;
is shash_getd($sh, sclstr_upgraded("")), !!1;
is_dg shash_get($sh, sclstr_downgraded("")), "b2";
is_dg shash_get($sh, sclstr_upgraded("")), "b2";
is shash_getd($sh, sclstr_downgraded("a3")), !!1;
is shash_getd($sh, sclstr_upgraded("a3")), !!1;
is_dg shash_get($sh, sclstr_downgraded("a3")), "b3";
is_dg shash_get($sh, sclstr_upgraded("a3")), "b3";
shash_set($sh, sclstr_upgraded(""), undef);
is shash_getd($sh, sclstr_downgraded("")), !!0;
is shash_getd($sh, sclstr_upgraded("")), !!0;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_get($sh, sclstr_upgraded("")), undef;

shash_set($sh, "c0", sclstr_downgraded(""));
shash_set($sh, "c1", sclstr_downgraded("d1"));
is_dg shash_get($sh, "c0"), "";
is_dg shash_get($sh, "c1"), "d1";
shash_set($sh, "c2", sclstr_upgraded(""));
shash_set($sh, "c3", sclstr_upgraded("d3"));
is_dg shash_get($sh, "c2"), "";
is_dg shash_get($sh, "c3"), "d3";

is shash_gset($sh, sclstr_downgraded(""), undef), undef;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_gset($sh, sclstr_downgraded(""), "e0a"), undef;
is_dg shash_get($sh, sclstr_downgraded("")), "e0a";
is_dg shash_gset($sh, sclstr_downgraded(""), "e0b"), "e0a";
is_dg shash_get($sh, sclstr_downgraded("")), "e0b";
is_dg shash_gset($sh, sclstr_downgraded(""), undef), "e0b";
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_gset($sh, sclstr_upgraded(""), undef), undef;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_gset($sh, sclstr_upgraded(""), "e1a"), undef;
is_dg shash_get($sh, sclstr_downgraded("")), "e1a";
is_dg shash_gset($sh, sclstr_upgraded(""), "e1b"), "e1a";
is_dg shash_get($sh, sclstr_downgraded("")), "e1b";
is_dg shash_gset($sh, sclstr_upgraded(""), undef), "e1b";
is shash_get($sh, sclstr_downgraded("")), undef;

is shash_gset($sh, "f0", sclstr_downgraded("")), undef;
is_dg shash_get($sh, "f0"), "";
is_dg shash_gset($sh, "f0", sclstr_downgraded("g0a")), "";
is_dg shash_get($sh, "f0"), "g0a";
is_dg shash_gset($sh, "f0", sclstr_downgraded("")), "g0a";
is_dg shash_get($sh, "f0"), "";
is_dg shash_gset($sh, "f0", undef), "";
is shash_get($sh, "f0"), undef;
is shash_gset($sh, "f1", sclstr_upgraded("")), undef;
is_dg shash_get($sh, "f1"), "";
is_dg shash_gset($sh, "f1", sclstr_upgraded("g1a")), "";
is_dg shash_get($sh, "f1"), "g1a";
is_dg shash_gset($sh, "f1", sclstr_upgraded("")), "g1a";
is_dg shash_get($sh, "f1"), "";
is_dg shash_gset($sh, "f1", undef), "";
is shash_get($sh, "f1"), undef;

is shash_cset($sh, sclstr_downgraded(""), undef, undef), !!1;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_cset($sh, sclstr_downgraded(""), "h0a", undef), !!0;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_cset($sh, sclstr_downgraded(""), "h0b", "h0c"), !!0;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_cset($sh, sclstr_downgraded(""), undef, "h0d"), !!1;
is_dg shash_get($sh, sclstr_downgraded("")), "h0d";
is shash_cset($sh, sclstr_downgraded(""), undef, undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("")), "h0d";
is shash_cset($sh, sclstr_downgraded(""), undef, "h0e"), !!0;
is_dg shash_get($sh, sclstr_downgraded("")), "h0d";
is shash_cset($sh, sclstr_downgraded(""), "h0f", undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("")), "h0d";
is shash_cset($sh, sclstr_downgraded(""), "h0f", "h0g"), !!0;
is_dg shash_get($sh, sclstr_downgraded("")), "h0d";
is shash_cset($sh, sclstr_downgraded(""), "h0d", "h0h"), !!1;
is_dg shash_get($sh, sclstr_downgraded("")), "h0h";
is shash_cset($sh, sclstr_downgraded(""), "h0h", undef), !!1;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_cset($sh, sclstr_upgraded(""), undef, undef), !!1;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_cset($sh, sclstr_upgraded(""), "h1a", undef), !!0;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_cset($sh, sclstr_upgraded(""), "h1b", "h1c"), !!0;
is shash_get($sh, sclstr_downgraded("")), undef;
is shash_cset($sh, sclstr_upgraded(""), undef, "h1d"), !!1;
is_dg shash_get($sh, sclstr_downgraded("")), "h1d";
is shash_cset($sh, sclstr_upgraded(""), undef, undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("")), "h1d";
is shash_cset($sh, sclstr_upgraded(""), undef, "h1e"), !!0;
is_dg shash_get($sh, sclstr_downgraded("")), "h1d";
is shash_cset($sh, sclstr_upgraded(""), "h1f", undef), !!0;
is_dg shash_get($sh, sclstr_downgraded("")), "h1d";
is shash_cset($sh, sclstr_upgraded(""), "h1f", "h1g"), !!0;
is_dg shash_get($sh, sclstr_downgraded("")), "h1d";
is shash_cset($sh, sclstr_upgraded(""), "h1d", "h1h"), !!1;
is_dg shash_get($sh, sclstr_downgraded("")), "h1h";
is shash_cset($sh, sclstr_upgraded(""), "h1h", undef), !!1;
is shash_get($sh, sclstr_downgraded("")), undef;

is shash_cset($sh, "i", sclstr_downgraded(""), undef), !!0;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "i", sclstr_downgraded(""), sclstr_downgraded("")), !!0;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "i", sclstr_downgraded(""), sclstr_downgraded("j0")), !!0;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "i", sclstr_downgraded("j1"), sclstr_downgraded("")), !!0;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "i", sclstr_downgraded("j1"), sclstr_downgraded("j0")), !!0;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "i", sclstr_downgraded("j1"), undef), !!0;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "i", undef, undef), !!1;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "i", undef, sclstr_downgraded("")), !!1;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", undef, undef), !!0;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", undef, sclstr_downgraded("")), !!0;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", undef, sclstr_downgraded("j2")), !!0;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", sclstr_downgraded("j3"), undef), !!0;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", sclstr_downgraded("j3"), sclstr_downgraded("")), !!0;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", sclstr_downgraded("j3"), sclstr_downgraded("j6")), !!0;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", sclstr_downgraded(""), sclstr_downgraded("j7")), !!1;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", undef, undef), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", undef, sclstr_downgraded("")), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", undef, sclstr_downgraded("j4")), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", sclstr_downgraded(""), undef), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", sclstr_downgraded(""), sclstr_downgraded("")), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", sclstr_downgraded(""), sclstr_downgraded("j5")), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", sclstr_downgraded("j3"), undef), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", sclstr_downgraded("j3"), sclstr_downgraded("")), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", sclstr_downgraded("j3"), sclstr_downgraded("j6")), !!0;
is_dg shash_get($sh, "i"), "j7";
is shash_cset($sh, "i", sclstr_downgraded("j7"), undef), !!1;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "i", undef, sclstr_downgraded("j8")), !!1;
is_dg shash_get($sh, "i"), "j8";
is shash_cset($sh, "i", sclstr_downgraded("j8"), sclstr_downgraded("j9")), !!1;
is_dg shash_get($sh, "i"), "j9";
is shash_cset($sh, "i", sclstr_downgraded("j9"), sclstr_downgraded("")), !!1;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", sclstr_downgraded(""), sclstr_downgraded("")), !!1;
is_dg shash_get($sh, "i"), "";
is shash_cset($sh, "i", sclstr_downgraded(""), undef), !!1;
is shash_get($sh, "i"), undef;
is shash_cset($sh, "k", sclstr_upgraded(""), undef), !!0;
is shash_get($sh, "k"), undef;
is shash_cset($sh, "k", sclstr_upgraded(""), sclstr_upgraded("")), !!0;
is shash_get($sh, "k"), undef;
is shash_cset($sh, "k", sclstr_upgraded(""), sclstr_upgraded("l0")), !!0;
is shash_get($sh, "k"), undef;
is shash_cset($sh, "k", sclstr_upgraded("l1"), sclstr_upgraded("")), !!0;
is shash_get($sh, "k"), undef;
is shash_cset($sh, "k", sclstr_upgraded("l1"), sclstr_upgraded("l0")), !!0;
is shash_get($sh, "k"), undef;
is shash_cset($sh, "k", sclstr_upgraded("l1"), undef), !!0;
is shash_get($sh, "k"), undef;
is shash_cset($sh, "k", undef, undef), !!1;
is shash_get($sh, "k"), undef;
is shash_cset($sh, "k", undef, sclstr_upgraded("")), !!1;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", undef, undef), !!0;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", undef, sclstr_upgraded("")), !!0;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", undef, sclstr_upgraded("l2")), !!0;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", sclstr_upgraded("l3"), undef), !!0;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", sclstr_upgraded("l3"), sclstr_upgraded("")), !!0;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", sclstr_upgraded("l3"), sclstr_upgraded("l6")), !!0;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", sclstr_upgraded(""), sclstr_upgraded("l7")), !!1;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", undef, undef), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", undef, sclstr_upgraded("")), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", undef, sclstr_upgraded("l4")), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", sclstr_upgraded(""), undef), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", sclstr_upgraded(""), sclstr_upgraded("")), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", sclstr_upgraded(""), sclstr_upgraded("l5")), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", sclstr_upgraded("l3"), undef), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", sclstr_upgraded("l3"), sclstr_upgraded("")), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", sclstr_upgraded("l3"), sclstr_upgraded("l6")), !!0;
is_dg shash_get($sh, "k"), "l7";
is shash_cset($sh, "k", sclstr_upgraded("l7"), undef), !!1;
is shash_get($sh, "k"), undef;
is shash_cset($sh, "k", undef, sclstr_upgraded("l8")), !!1;
is_dg shash_get($sh, "k"), "l8";
is shash_cset($sh, "k", sclstr_upgraded("l8"), sclstr_upgraded("l9")), !!1;
is_dg shash_get($sh, "k"), "l9";
is shash_cset($sh, "k", sclstr_upgraded("l9"), sclstr_upgraded("")), !!1;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", sclstr_upgraded(""), sclstr_upgraded("")), !!1;
is_dg shash_get($sh, "k"), "";
is shash_cset($sh, "k", sclstr_upgraded(""), undef), !!1;
is shash_get($sh, "k"), undef;

require_ok "Hash::SharedMem::Handle";
my %sh;
tie %sh, "Hash::SharedMem::Handle", $sh;
ok is_shash(tied(%sh));
ok tied(%sh) == $sh;

is exists($sh{sclstr_downgraded("")}), !!0;
is exists($sh{sclstr_upgraded("")}), !!0;
is $sh{sclstr_downgraded("")}, undef;
is $sh{sclstr_upgraded("")}, undef;
$sh{sclstr_downgraded("")} = "n0";
$sh{sclstr_downgraded("m1")} = "n1";
is exists($sh{sclstr_downgraded("")}), !!1;
is exists($sh{sclstr_upgraded("")}), !!1;
is_dg $sh{sclstr_downgraded("")}, "n0";
is_dg $sh{sclstr_upgraded("")}, "n0";
is exists($sh{sclstr_downgraded("m1")}), !!1;
is exists($sh{sclstr_upgraded("m1")}), !!1;
is_dg $sh{sclstr_downgraded("m1")}, "n1";
is_dg $sh{sclstr_upgraded("m1")}, "n1";
is_dg delete($sh{sclstr_downgraded("")}), "n0";
is exists($sh{sclstr_downgraded("")}), !!0;
is exists($sh{sclstr_upgraded("")}), !!0;
is $sh{sclstr_downgraded("")}, undef;
is $sh{sclstr_upgraded("")}, undef;
$sh{sclstr_upgraded("")} = "n2";
$sh{sclstr_upgraded("m3")} = "n3";
is exists($sh{sclstr_downgraded("")}), !!1;
is exists($sh{sclstr_upgraded("")}), !!1;
is_dg $sh{sclstr_downgraded("")}, "n2";
is_dg $sh{sclstr_upgraded("")}, "n2";
is exists($sh{sclstr_downgraded("m3")}), !!1;
is exists($sh{sclstr_upgraded("m3")}), !!1;
is_dg $sh{sclstr_downgraded("m3")}, "n3";
is_dg $sh{sclstr_upgraded("m3")}, "n3";
is_dg delete($sh{sclstr_upgraded("")}), "n2";
is exists($sh{sclstr_downgraded("")}), !!0;
is exists($sh{sclstr_upgraded("")}), !!0;
is $sh{sclstr_downgraded("")}, undef;
is $sh{sclstr_upgraded("")}, undef;
is delete($sh{sclstr_downgraded("")}), undef;
is delete($sh{sclstr_upgraded("")}), undef;

$sh{o0} = sclstr_downgraded("");
$sh{o1} = sclstr_downgraded("p1");
is_dg shash_get($sh, "o0"), "";
is_dg shash_get($sh, "o1"), "p1";
$sh{o2} = sclstr_upgraded("");
$sh{o3} = sclstr_upgraded("p3");
is_dg shash_get($sh, "o2"), "";
is_dg shash_get($sh, "o3"), "p3";

1;