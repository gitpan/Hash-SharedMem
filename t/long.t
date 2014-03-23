use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 8;

BEGIN { use_ok "Hash::SharedMem", qw(is_shash shash_open shash_get shash_set); }

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = shash_open("$tmpdir/t0", "rwc");
ok $sh;
ok is_shash($sh);
my %ph;

sub doru($) { defined($_[0]) ? $_[0] : "u" }

sub check_hash_state() {
	my $ok = 1;
	foreach my $k (sort keys %ph) {
		$ok &&= doru(shash_get($sh, $k)) eq $ph{$k};
	}
	ok $ok;
}

my $p = 5;
my $q = 5;
for(my $i = 0; $i != 5; $i++) {
	for(my $j = 0; $j != 100; $j++) {
		$p = ($p*21+7) % 100000;
		$q = ($q*41+17) % 100000;
		my $k = join("x", map { $p.$_ } 0..($p % 1000));
		my $v = join("x", map { $q.$_ } 0..($q % 1000));
		shash_set($sh, $k, $v);
		$ph{$k} = $v;
	}
	check_hash_state();
}

1;
