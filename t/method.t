use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 200;

BEGIN { use_ok "Hash::SharedMem::Handle"; }
BEGIN { use_ok "Hash::SharedMem", qw(is_shash); }

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = Hash::SharedMem::Handle->open("$tmpdir/t0", "rwc");
ok $sh;
ok is_shash($sh);
is scalar($sh->is_snapshot), !!0;
is_deeply [$sh->is_snapshot], [!!0];
is scalar($sh->is_readable), !!1;
is_deeply [$sh->is_readable], [!!1];
is scalar($sh->is_writable), !!1;
is_deeply [$sh->is_writable], [!!1];
is scalar($sh->mode), "rw";
is_deeply [$sh->mode], ["rw"];

is scalar($sh->getd("a100")), !!0;
is_deeply [$sh->getd("a100")], [!!0];
is scalar($sh->get("a100")), undef;
is_deeply [$sh->get("a100")], [undef];

$sh->set("a110", "b110");
is scalar($sh->set("a100", "b100")), undef;
is_deeply [$sh->set("a120", "b120")], [];

is scalar($sh->getd("a100")), !!1;
is_deeply [$sh->getd("a100")], [!!1];
is scalar($sh->get("a100")), "b100";
is_deeply [$sh->get("a100")], ["b100"];

is scalar($sh->getd("a000")), !!0;
is scalar($sh->get("a000")), undef;
is scalar($sh->getd("a105")), !!0;
is scalar($sh->get("a105")), undef;
is scalar($sh->getd("a110")), !!1;
is scalar($sh->get("a110")), "b110";
is scalar($sh->getd("a115")), !!0;
is scalar($sh->get("a115")), undef;
is scalar($sh->getd("a120")), !!1;
is scalar($sh->get("a120")), "b120";
is scalar($sh->getd("a130")), !!0;
is scalar($sh->get("a130")), undef;

my $sn = $sh->snapshot;
ok is_shash($sn);
is scalar($sn->is_snapshot), !!1;
is_deeply [$sn->is_snapshot], [!!1];
is scalar($sn->is_readable), !!1;
is_deeply [$sn->is_readable], [!!1];
is scalar($sn->is_writable), !!0;
is_deeply [$sn->is_writable], [!!0];
is scalar($sn->mode), "r";
is_deeply [$sn->mode], ["r"];

is $sn->getd("a000"), !!0;
is $sn->get("a000"), undef;
is $sn->getd("a100"), !!1;
is $sn->get("a100"), "b100";
is $sn->getd("a105"), !!0;
is $sn->get("a105"), undef;
is $sn->getd("a110"), !!1;
is $sn->get("a110"), "b110";
is $sn->getd("a115"), !!0;
is $sn->get("a115"), undef;
is $sn->getd("a120"), !!1;
is $sn->get("a120"), "b120";
is $sn->getd("a130"), !!0;
is $sn->get("a130"), undef;

$sh->set("a105", "b105");
$sh->set("a110", undef);

is $sh->getd("a000"), !!0;
is $sh->get("a000"), undef;
is $sh->getd("a100"), !!1;
is $sh->get("a100"), "b100";
is $sh->getd("a105"), !!1;
is $sh->get("a105"), "b105";
is $sh->getd("a110"), !!0;
is $sh->get("a110"), undef;
is $sh->getd("a115"), !!0;
is $sh->get("a115"), undef;
is $sh->getd("a120"), !!1;
is $sh->get("a120"), "b120";
is $sh->getd("a130"), !!0;
is $sh->get("a130"), undef;

is $sn->getd("a000"), !!0;
is $sn->get("a000"), undef;
is $sn->getd("a100"), !!1;
is $sn->get("a100"), "b100";
is $sn->getd("a105"), !!0;
is $sn->get("a105"), undef;
is $sn->getd("a110"), !!1;
is $sn->get("a110"), "b110";
is $sn->getd("a115"), !!0;
is $sn->get("a115"), undef;
is $sn->getd("a120"), !!1;
is $sn->get("a120"), "b120";
is $sn->getd("a130"), !!0;
is $sn->get("a130"), undef;

eval { $sn->set("a115", "b115") };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t0:
		\ shared\ hash\ handle\ is\ a\ snapshot\ #x;
is $sh->getd("a115"), !!0;
is $sh->get("a115"), undef;
is $sn->getd("a115"), !!0;
is $sn->get("a115"), undef;

$sh->gset("a115", "c115");
is $sh->get("a115"), "c115";
$sh->gset("a115", "d115");
is $sh->get("a115"), "d115";
$sh->gset("a115", "d115");
is $sh->get("a115"), "d115";
$sh->gset("a115", undef);
is $sh->get("a115"), undef;
$sh->gset("a115", undef);
is $sh->get("a115"), undef;

is scalar($sh->gset("a115", "e115")), undef;
is $sh->get("a115"), "e115";
is scalar($sh->gset("a115", "f115")), "e115";
is $sh->get("a115"), "f115";
is scalar($sh->gset("a115", "f115")), "f115";
is $sh->get("a115"), "f115";
is scalar($sh->gset("a115", undef)), "f115";
is $sh->get("a115"), undef;
is scalar($sh->gset("a115", undef)), undef;
is $sh->get("a115"), undef;

is_deeply [$sh->gset("a115", "g115")], [undef];
is $sh->get("a115"), "g115";
is_deeply [$sh->gset("a115", "h115")], ["g115"];
is $sh->get("a115"), "h115";
is_deeply [$sh->gset("a115", "h115")], ["h115"];
is $sh->get("a115"), "h115";
is_deeply [$sh->gset("a115", undef)], ["h115"];
is $sh->get("a115"), undef;
is_deeply [$sh->gset("a115", undef)], [undef];
is $sh->get("a115"), undef;

$sh->cset("a115", "z", "i115");
is $sh->get("a115"), undef;
$sh->cset("a115", undef, "j115");
is $sh->get("a115"), "j115";
$sh->cset("a115", "z", "k115");
is $sh->get("a115"), "j115";
$sh->cset("a115", undef, "l115");
is $sh->get("a115"), "j115";
$sh->cset("a115", "j115", "m115");
is $sh->get("a115"), "m115";
$sh->cset("a115", "z", "m115");
is $sh->get("a115"), "m115";
$sh->cset("a115", undef, "m115");
is $sh->get("a115"), "m115";
$sh->cset("a115", "m115", "m115");
is $sh->get("a115"), "m115";
$sh->cset("a115", "z", undef);
is $sh->get("a115"), "m115";
$sh->cset("a115", undef, undef);
is $sh->get("a115"), "m115";
$sh->cset("a115", "m115", undef);
is $sh->get("a115"), undef;
$sh->cset("a115", "z", undef);
is $sh->get("a115"), undef;
$sh->cset("a115", undef, undef);
is $sh->get("a115"), undef;

is scalar($sh->cset("a115", "z", "i115")), !!0;
is $sh->get("a115"), undef;
is scalar($sh->cset("a115", undef, "j115")), !!1;
is $sh->get("a115"), "j115";
is scalar($sh->cset("a115", "z", "k115")), !!0;
is $sh->get("a115"), "j115";
is scalar($sh->cset("a115", undef, "l115")), !!0;
is $sh->get("a115"), "j115";
is scalar($sh->cset("a115", "j115", "m115")), !!1;
is $sh->get("a115"), "m115";
is scalar($sh->cset("a115", "z", "m115")), !!0;
is $sh->get("a115"), "m115";
is scalar($sh->cset("a115", undef, "m115")), !!0;
is $sh->get("a115"), "m115";
is scalar($sh->cset("a115", "m115", "m115")), !!1;
is $sh->get("a115"), "m115";
is scalar($sh->cset("a115", "z", undef)), !!0;
is $sh->get("a115"), "m115";
is scalar($sh->cset("a115", undef, undef)), !!0;
is $sh->get("a115"), "m115";
is scalar($sh->cset("a115", "m115", undef)), !!1;
is $sh->get("a115"), undef;
is scalar($sh->cset("a115", "z", undef)), !!0;
is $sh->get("a115"), undef;
is scalar($sh->cset("a115", undef, undef)), !!1;
is $sh->get("a115"), undef;

is_deeply [$sh->cset("a115", "z", "i115")], [!!0];
is $sh->get("a115"), undef;
is_deeply [$sh->cset("a115", undef, "j115")], [!!1];
is $sh->get("a115"), "j115";
is_deeply [$sh->cset("a115", "z", "k115")], [!!0];
is $sh->get("a115"), "j115";
is_deeply [$sh->cset("a115", undef, "l115")], [!!0];
is $sh->get("a115"), "j115";
is_deeply [$sh->cset("a115", "j115", "m115")], [!!1];
is $sh->get("a115"), "m115";
is_deeply [$sh->cset("a115", "z", "m115")], [!!0];
is $sh->get("a115"), "m115";
is_deeply [$sh->cset("a115", undef, "m115")], [!!0];
is $sh->get("a115"), "m115";
is_deeply [$sh->cset("a115", "m115", "m115")], [!!1];
is $sh->get("a115"), "m115";
is_deeply [$sh->cset("a115", "z", undef)], [!!0];
is $sh->get("a115"), "m115";
is_deeply [$sh->cset("a115", undef, undef)], [!!0];
is $sh->get("a115"), "m115";
is_deeply [$sh->cset("a115", "m115", undef)], [!!1];
is $sh->get("a115"), undef;
is_deeply [$sh->cset("a115", "z", undef)], [!!0];
is $sh->get("a115"), undef;
is_deeply [$sh->cset("a115", undef, undef)], [!!1];
is $sh->get("a115"), undef;

$sh->tidy;
is scalar($sh->tidy), undef;
is_deeply [$sh->tidy], [];

my $nx = Hash::SharedMem::Handle->open("$tmpdir/t1", "c");
ok $nx;
ok is_shash($nx);
is scalar($nx->is_snapshot), !!0;
is_deeply [$nx->is_snapshot], [!!0];
is scalar($nx->is_readable), !!0;
is_deeply [$nx->is_readable], [!!0];
is scalar($nx->is_writable), !!0;
is_deeply [$nx->is_writable], [!!0];
is scalar($nx->mode), "";
is_deeply [$nx->mode], [""];
eval { $nx->getd("a100") };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { $nx->get("a100") };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { $nx->set("a100", "b100") };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;
eval { $nx->gset("a100", "b100") };
like $@, qr#\Acan't\ update\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { $nx->cset("a100", "b100", "c100") };
like $@, qr#\Acan't\ update\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;

eval { Hash::SharedMem::Handle->open("$tmpdir/t1", "c") };
is $@, "";
my @sh = Hash::SharedMem::Handle->open("$tmpdir/t1", "c");
is scalar(@sh), 1;
ok is_shash($sh[0]);

1;
