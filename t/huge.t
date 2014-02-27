use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 4;

BEGIN { use_ok "Hash::SharedMem", qw(is_shash shash_open shash_get shash_set); }

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = shash_open("$tmpdir/t0", "rwc");
ok $sh;
ok is_shash($sh);

my $tstr = join("", map { sprintf("abcd%6d", $_) } 0..999_999);
shash_set($sh, "xyz", $tstr);
is shash_get($sh, "xyz"), $tstr;

1;
