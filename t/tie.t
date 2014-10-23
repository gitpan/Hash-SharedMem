use warnings;
use strict;

use File::Temp 0.22 qw(tempdir);
use Test::More tests => 100;

BEGIN { use_ok "Hash::SharedMem::Handle"; }
BEGIN { use_ok "Hash::SharedMem", qw(is_shash); }

my $tmpdir = tempdir(CLEANUP => 1);
my $sh = Hash::SharedMem::Handle->open("$tmpdir/t0", "rwc");
ok $sh;
ok is_shash($sh);

my %sh;
eval { tie %sh, "Hash::SharedMem::Handle" };
isnt $@, "";
eval { tie %sh, "Hash::SharedMem::Handle", "x", "y", "z" };
isnt $@, "";
eval { tie %sh, "Hash::SharedMem::Handle", 2 };
like $@, qr/\Ahandle is not a shared hash handle /;
eval { tie %sh, "Hash::SharedMem::Handle", $sh };
is $@, "";
ok is_shash(tied(%sh));
ok tied(%sh) == $sh;

ok !exists($sh{a100});
is $sh{a100}, undef;

$sh{a110} = "b110";
$sh{a100} = "b100";
$sh{a120} = "b120";

ok !exists($sh{a000});
is $sh{a000}, undef;
ok exists($sh{a100});
is $sh{a100}, "b100";
ok !exists($sh{a105});
is $sh{a105}, undef;
ok exists($sh{a110});
is $sh{a110}, "b110";
ok !exists($sh{a115});
is $sh{a115}, undef;
ok exists($sh{a120});
is $sh{a120}, "b120";
ok !exists($sh{a130});
is $sh{a130}, undef;

eval { $sh{a150} = undef };
like $@, qr/\Anew value is not an octet string /;
ok !exists($sh{a150});
is $sh{a150}, undef;

$sh{a105} = "b105";
delete $sh{a110};

ok !exists($sh{a000});
is $sh{a000}, undef;
ok exists($sh{a100});
is $sh{a100}, "b100";
ok exists($sh{a105});
is $sh{a105}, "b105";
ok !exists($sh{a110});
is $sh{a110}, undef;
ok !exists($sh{a115});
is $sh{a115}, undef;
ok exists($sh{a120});
is $sh{a120}, "b120";
ok !exists($sh{a130});
is $sh{a130}, undef;

is delete($sh{a115}), undef;
is delete($sh{a120}), "b120";
is delete($sh{a120}), undef;
ok !exists($sh{a115});
is $sh{a115}, undef;
ok !exists($sh{a120});
is $sh{a120}, undef;
$sh{a120} = "b120";

$sh = undef;
untie %sh;
ok !exists($sh{a120});
eval { tie %sh, "Hash::SharedMem::Handle", "$tmpdir/t0", "rwc" };
is $@, "";

ok !exists($sh{a000});
is $sh{a000}, undef;
ok exists($sh{a100});
is $sh{a100}, "b100";
ok exists($sh{a105});
is $sh{a105}, "b105";
ok !exists($sh{a110});
is $sh{a110}, undef;
ok !exists($sh{a115});
is $sh{a115}, undef;
ok exists($sh{a120});
is $sh{a120}, "b120";
ok !exists($sh{a130});
is $sh{a130}, undef;

untie %sh;
ok !exists($sh{a120});
eval { tie %sh, "Hash::SharedMem::Handle", "$tmpdir/t0", "r" };
is $@, "";

ok exists($sh{a120});
is $sh{a120}, "b120";
eval { $sh{a100} = "b100" };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t0:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;
eval { $sh{a101} = "b101" };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t0:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;
eval { my $z = delete $sh{a100} };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t0:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;
eval { my $z = delete $sh{a101} };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t0:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;
eval { delete $sh{a100} };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t0:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;
eval { delete $sh{a101} };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t0:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;

untie %sh;
ok !exists($sh{a120});
eval { tie %sh, "Hash::SharedMem::Handle", "$tmpdir/t1", "c" };
is $@, "";

eval { my $z = exists($sh{a100}) };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { my $z = $sh{a100} };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { $sh{a100} = "b100" };
like $@, qr#\Acan't\ write\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unwritable\ mode\ #x;
eval { my $z = delete $sh{a100} };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { delete $sh{a100} };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;

untie %sh;
ok !exists($sh{a120});
eval { tie %sh, "Hash::SharedMem::Handle", "$tmpdir/t1", "wc" };
is $@, "";

eval { my $z = exists($sh{a100}) };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { my $z = $sh{a100} };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { $sh{a100} = "b100" };
is $@, "";
eval { my $z = delete $sh{a100} };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;
eval { delete $sh{a100} };
like $@, qr#\Acan't\ read\ shared\ hash\ \Q$tmpdir\E/t1:
		\ shared\ hash\ was\ opened\ in\ unreadable\ mode\ #x;

eval { %sh = () };
like $@, qr/\Acan't clear shared hash at/;
eval { %sh = ( abc => "def" ) };
like $@, qr/\Acan't clear shared hash at/;
eval { my @z = keys %sh };
like $@, qr/\Acan't enumerate shared hash at/;
eval { my $z = keys %sh };
like $@, qr/\Acan't enumerate shared hash at/;
eval { my @z = values %sh };
like $@, qr/\Acan't enumerate shared hash at/;
eval { my $z = values %sh };
like $@, qr/\Acan't enumerate shared hash at/;
eval { my @z = each %sh };
like $@, qr/\Acan't enumerate shared hash at/;
eval { my $z = each %sh };
like $@, qr/\Acan't enumerate shared hash at/;
eval { my @z = %sh };
like $@, qr/\Acan't enumerate shared hash at/;
SKIP: {
	skip "tied hash in scalar context not supported on this Perl", 1
		unless ("$]" >= 5.008003 && "$]" < 5.009000) ||
			"$]" >= 5.009001;
	eval { my $z = %sh };
	like $@, qr/\Acan't check occupancy of shared hash at/;
}

1;
