use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 5005;

BEGIN { use_ok "Hash::SharedMem", qw(is_shash shash_open shash_get shash_set); }

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = shash_open("$tmpdir/t0", "rwc");
ok $sh;
ok is_shash($sh);

my $genstr = join("x", 0..1222);
my %orig;
for(my $i = 0; $i != 5000; $i++) {
	my $s = substr($i."_".$genstr, 0, $i);
	shash_set($sh, $i, $s);
	$orig{$i} = \$s;
}
my %get;
for(my $i = 0; $i != 5000; $i++) {
	$get{$i} = \shash_get($sh, $i);
}
is_deeply \%get, \%orig;
$sh = undef;
is_deeply \%get, \%orig;
for(my $i = 0; $i != 5000; $i++) {
	eval { ${$get{$i}} = undef; };
	like $@, qr/\AModification of a read-only value attempted /;
}

1;
