use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 183;

BEGIN { use_ok "Hash::SharedMem", qw(is_shash shash_open shash_get shash_set); }

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = shash_open("$tmpdir/t0", "rwc");
ok $sh;
ok is_shash($sh);
my %ph;

sub check_hash_state() {
	my $ok = 1;
	for(my $v = 0; $v != 100000; $v++) {
		$ok &&= (shash_get($sh, $v) // "u") eq ($ph{$v} // "u");
	}
	ok $ok;
}

my $v = 5;
for(my $i = 0; $i != 40; $i++) {
	for(my $j = 0; $j != 1000; $j++) {
		$v = ($v*21+7) % 100000;
		shash_set($sh, $v, "a".$v);
		$ph{$v} = "a".$v;
	}
	check_hash_state();
}

$v = 5;
for(my $i = 0; $i != 40; $i++) {
	for(my $j = 0; $j != 1000; $j++) {
		$v = ($v*61+19) % 100000;
		shash_set($sh, $v, "b".$v);
		$ph{$v} = "b".$v;
	}
	check_hash_state();
}

$v = 5;
for(my $i = 0; $i != 100; $i++) {
	for(my $j = 0; $j != 1000; $j++) {
		$v = ($v*41+17) % 100000;
		shash_set($sh, $v, undef);
		delete $ph{$v};
	}
	check_hash_state();
}

1;
