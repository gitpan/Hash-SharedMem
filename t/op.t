use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 214;

BEGIN { use_ok "Hash::SharedMem", qw(
	is_shash check_shash
	shash_open
	shash_is_readable shash_is_writable shash_mode
	shash_getd shash_get shash_set shash_gset shash_cset
	shash_snapshot shash_is_snapshot
	shash_tidy
); }

is scalar(is_shash("foo")), !!0;
is_deeply [is_shash("foo")], [!!0];
eval { check_shash("foo") };
like $@, qr/\Ahandle is not a shared hash handle /;

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = shash_open("$tmpdir/t0", "rwc");
ok $sh;
is scalar(is_shash($sh)), !!1;
is_deeply [is_shash($sh)], [!!1];
eval { check_shash($sh) };
is $@, "";
is scalar(check_shash($sh)), undef;
is_deeply [check_shash($sh)], [];
is scalar(shash_is_snapshot($sh)), !!0;
is_deeply [shash_is_snapshot($sh)], [!!0];
is scalar(shash_is_readable($sh)), !!1;
is_deeply [shash_is_readable($sh)], [!!1];
is scalar(shash_is_writable($sh)), !!1;
is_deeply [shash_is_writable($sh)], [!!1];
is scalar(shash_mode($sh)), "rw";
is_deeply [shash_mode($sh)], ["rw"];

is scalar(shash_getd($sh, "a100")), !!0;
is_deeply [shash_getd($sh, "a100")], [!!0];
is scalar(shash_get($sh, "a100")), undef;
is_deeply [shash_get($sh, "a100")], [undef];

shash_set($sh, "a110", "b110");
is scalar(shash_set($sh, "a100", "b100")), undef;
is_deeply [shash_set($sh, "a120", "b120")], [];

is scalar(shash_getd($sh, "a100")), !!1;
is_deeply [shash_getd($sh, "a100")], [!!1];
is scalar(shash_get($sh, "a100")), "b100";
is_deeply [shash_get($sh, "a100")], ["b100"];

is scalar(shash_getd($sh, "a000")), !!0;
is scalar(shash_get($sh, "a000")), undef;
is scalar(shash_getd($sh, "a105")), !!0;
is scalar(shash_get($sh, "a105")), undef;
is scalar(shash_getd($sh, "a110")), !!1;
is scalar(shash_get($sh, "a110")), "b110";
is scalar(shash_getd($sh, "a115")), !!0;
is scalar(shash_get($sh, "a115")), undef;
is scalar(shash_getd($sh, "a120")), !!1;
is scalar(shash_get($sh, "a120")), "b120";
is scalar(shash_getd($sh, "a130")), !!0;
is scalar(shash_get($sh, "a130")), undef;

my $sn = shash_snapshot($sh);
is scalar(is_shash($sn)), !!1;
is_deeply [is_shash($sn)], [!!1];
eval { check_shash($sn) };
is $@, "";
is scalar(check_shash($sn)), undef;
is_deeply [check_shash($sn)], [];
is scalar(shash_is_snapshot($sn)), !!1;
is_deeply [shash_is_snapshot($sn)], [!!1];
is scalar(shash_is_readable($sn)), !!1;
is_deeply [shash_is_readable($sn)], [!!1];
is scalar(shash_is_writable($sn)), !!0;
is_deeply [shash_is_writable($sn)], [!!0];
is scalar(shash_mode($sn)), "r";
is_deeply [shash_mode($sn)], ["r"];

is shash_getd($sn, "a000"), !!0;
is shash_get($sn, "a000"), undef;
is shash_getd($sn, "a100"), !!1;
is shash_get($sn, "a100"), "b100";
is shash_getd($sn, "a105"), !!0;
is shash_get($sn, "a105"), undef;
is shash_getd($sn, "a110"), !!1;
is shash_get($sn, "a110"), "b110";
is shash_getd($sn, "a115"), !!0;
is shash_get($sn, "a115"), undef;
is shash_getd($sn, "a120"), !!1;
is shash_get($sn, "a120"), "b120";
is shash_getd($sn, "a130"), !!0;
is shash_get($sn, "a130"), undef;

shash_set($sh, "a105", "b105");
shash_set($sh, "a110", undef);

is shash_getd($sh, "a000"), !!0;
is shash_get($sh, "a000"), undef;
is shash_getd($sh, "a100"), !!1;
is shash_get($sh, "a100"), "b100";
is shash_getd($sh, "a105"), !!1;
is shash_get($sh, "a105"), "b105";
is shash_getd($sh, "a110"), !!0;
is shash_get($sh, "a110"), undef;
is shash_getd($sh, "a115"), !!0;
is shash_get($sh, "a115"), undef;
is shash_getd($sh, "a120"), !!1;
is shash_get($sh, "a120"), "b120";
is shash_getd($sh, "a130"), !!0;
is shash_get($sh, "a130"), undef;

is shash_getd($sn, "a000"), !!0;
is shash_get($sn, "a000"), undef;
is shash_getd($sn, "a100"), !!1;
is shash_get($sn, "a100"), "b100";
is shash_getd($sn, "a105"), !!0;
is shash_get($sn, "a105"), undef;
is shash_getd($sn, "a110"), !!1;
is shash_get($sn, "a110"), "b110";
is shash_getd($sn, "a115"), !!0;
is shash_get($sn, "a115"), undef;
is shash_getd($sn, "a120"), !!1;
is shash_get($sn, "a120"), "b120";
is shash_getd($sn, "a130"), !!0;
is shash_get($sn, "a130"), undef;

eval { shash_set($sn, "a115", "b115") };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t0:
		\ shared\ hash\ handle\ is\ a\ snapshot\ #x;
is shash_getd($sh, "a115"), !!0;
is shash_get($sh, "a115"), undef;
is shash_getd($sn, "a115"), !!0;
is shash_get($sn, "a115"), undef;

shash_gset($sh, "a115", "c115");
is shash_get($sh, "a115"), "c115";
shash_gset($sh, "a115", "d115");
is shash_get($sh, "a115"), "d115";
shash_gset($sh, "a115", "d115");
is shash_get($sh, "a115"), "d115";
shash_gset($sh, "a115", undef);
is shash_get($sh, "a115"), undef;
shash_gset($sh, "a115", undef);
is shash_get($sh, "a115"), undef;

is scalar(shash_gset($sh, "a115", "e115")), undef;
is shash_get($sh, "a115"), "e115";
is scalar(shash_gset($sh, "a115", "f115")), "e115";
is shash_get($sh, "a115"), "f115";
is scalar(shash_gset($sh, "a115", "f115")), "f115";
is shash_get($sh, "a115"), "f115";
is scalar(shash_gset($sh, "a115", undef)), "f115";
is shash_get($sh, "a115"), undef;
is scalar(shash_gset($sh, "a115", undef)), undef;
is shash_get($sh, "a115"), undef;

is_deeply [shash_gset($sh, "a115", "g115")], [undef];
is shash_get($sh, "a115"), "g115";
is_deeply [shash_gset($sh, "a115", "h115")], ["g115"];
is shash_get($sh, "a115"), "h115";
is_deeply [shash_gset($sh, "a115", "h115")], ["h115"];
is shash_get($sh, "a115"), "h115";
is_deeply [shash_gset($sh, "a115", undef)], ["h115"];
is shash_get($sh, "a115"), undef;
is_deeply [shash_gset($sh, "a115", undef)], [undef];
is shash_get($sh, "a115"), undef;

shash_cset($sh, "a115", "z", "i115");
is shash_get($sh, "a115"), undef;
shash_cset($sh, "a115", undef, "j115");
is shash_get($sh, "a115"), "j115";
shash_cset($sh, "a115", "z", "k115");
is shash_get($sh, "a115"), "j115";
shash_cset($sh, "a115", undef, "l115");
is shash_get($sh, "a115"), "j115";
shash_cset($sh, "a115", "j115", "m115");
is shash_get($sh, "a115"), "m115";
shash_cset($sh, "a115", "z", "m115");
is shash_get($sh, "a115"), "m115";
shash_cset($sh, "a115", undef, "m115");
is shash_get($sh, "a115"), "m115";
shash_cset($sh, "a115", "m115", "m115");
is shash_get($sh, "a115"), "m115";
shash_cset($sh, "a115", "z", undef);
is shash_get($sh, "a115"), "m115";
shash_cset($sh, "a115", undef, undef);
is shash_get($sh, "a115"), "m115";
shash_cset($sh, "a115", "m115", undef);
is shash_get($sh, "a115"), undef;
shash_cset($sh, "a115", "z", undef);
is shash_get($sh, "a115"), undef;
shash_cset($sh, "a115", undef, undef);
is shash_get($sh, "a115"), undef;

is scalar(shash_cset($sh, "a115", "z", "i115")), !!0;
is shash_get($sh, "a115"), undef;
is scalar(shash_cset($sh, "a115", undef, "j115")), !!1;
is shash_get($sh, "a115"), "j115";
is scalar(shash_cset($sh, "a115", "z", "k115")), !!0;
is shash_get($sh, "a115"), "j115";
is scalar(shash_cset($sh, "a115", undef, "l115")), !!0;
is shash_get($sh, "a115"), "j115";
is scalar(shash_cset($sh, "a115", "j115", "m115")), !!1;
is shash_get($sh, "a115"), "m115";
is scalar(shash_cset($sh, "a115", "z", "m115")), !!0;
is shash_get($sh, "a115"), "m115";
is scalar(shash_cset($sh, "a115", undef, "m115")), !!0;
is shash_get($sh, "a115"), "m115";
is scalar(shash_cset($sh, "a115", "m115", "m115")), !!1;
is shash_get($sh, "a115"), "m115";
is scalar(shash_cset($sh, "a115", "z", undef)), !!0;
is shash_get($sh, "a115"), "m115";
is scalar(shash_cset($sh, "a115", undef, undef)), !!0;
is shash_get($sh, "a115"), "m115";
is scalar(shash_cset($sh, "a115", "m115", undef)), !!1;
is shash_get($sh, "a115"), undef;
is scalar(shash_cset($sh, "a115", "z", undef)), !!0;
is shash_get($sh, "a115"), undef;
is scalar(shash_cset($sh, "a115", undef, undef)), !!1;
is shash_get($sh, "a115"), undef;

is_deeply [shash_cset($sh, "a115", "z", "i115")], [!!0];
is shash_get($sh, "a115"), undef;
is_deeply [shash_cset($sh, "a115", undef, "j115")], [!!1];
is shash_get($sh, "a115"), "j115";
is_deeply [shash_cset($sh, "a115", "z", "k115")], [!!0];
is shash_get($sh, "a115"), "j115";
is_deeply [shash_cset($sh, "a115", undef, "l115")], [!!0];
is shash_get($sh, "a115"), "j115";
is_deeply [shash_cset($sh, "a115", "j115", "m115")], [!!1];
is shash_get($sh, "a115"), "m115";
is_deeply [shash_cset($sh, "a115", "z", "m115")], [!!0];
is shash_get($sh, "a115"), "m115";
is_deeply [shash_cset($sh, "a115", undef, "m115")], [!!0];
is shash_get($sh, "a115"), "m115";
is_deeply [shash_cset($sh, "a115", "m115", "m115")], [!!1];
is shash_get($sh, "a115"), "m115";
is_deeply [shash_cset($sh, "a115", "z", undef)], [!!0];
is shash_get($sh, "a115"), "m115";
is_deeply [shash_cset($sh, "a115", undef, undef)], [!!0];
is shash_get($sh, "a115"), "m115";
is_deeply [shash_cset($sh, "a115", "m115", undef)], [!!1];
is shash_get($sh, "a115"), undef;
is_deeply [shash_cset($sh, "a115", "z", undef)], [!!0];
is shash_get($sh, "a115"), undef;
is_deeply [shash_cset($sh, "a115", undef, undef)], [!!1];
is shash_get($sh, "a115"), undef;

shash_tidy($sh);
is scalar(shash_tidy($sh)), undef;
is_deeply [shash_tidy($sh)], [];

my $nx = shash_open("$tmpdir/t1", "c");
ok $nx;
is scalar(is_shash($nx)), !!1;
is_deeply [is_shash($nx)], [!!1];
eval { check_shash($nx) };
is $@, "";
is scalar(check_shash($nx)), undef;
is_deeply [check_shash($nx)], [];
is scalar(shash_is_snapshot($nx)), !!0;
is_deeply [shash_is_snapshot($nx)], [!!0];
is scalar(shash_is_readable($nx)), !!0;
is_deeply [shash_is_readable($nx)], [!!0];
is scalar(shash_is_writable($nx)), !!0;
is_deeply [shash_is_writable($nx)], [!!0];
is scalar(shash_mode($nx)), "";
is_deeply [shash_mode($nx)], [""];
eval { shash_getd($nx, "a100") };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { shash_get($nx, "a100") };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { shash_set($nx, "a100", "b100") };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;
eval { shash_gset($nx, "a100", "b100") };
like $@, qr#\Acan't\ update\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { shash_cset($nx, "a100", "b100", "c100") };
like $@, qr#\Acan't\ update\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;

eval { shash_open("$tmpdir/t1", "c") };
is $@, "";
my @sh = shash_open("$tmpdir/t1", "c");
is scalar(@sh), 1;
ok is_shash($sh[0]);

1;
