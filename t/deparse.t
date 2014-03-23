use warnings;
use strict;

use Test::More;

BEGIN {
	unless("$]" >= 5.013007) {
		plan skip_all => "custom ops not registered on this Perl";
	}
	unless(eval { require B::Deparse; B::Deparse->VERSION(1.01); 1 }) {
		plan skip_all => "B::Deparse unavailable";
	}
}

BEGIN { plan tests => 14; }

BEGIN { use_ok "Hash::SharedMem", qw(
	is_shash check_shash
	shash_open
	shash_is_readable shash_is_writable shash_mode
	shash_getd shash_get shash_set shash_gset shash_cset
	shash_snapshot shash_is_snapshot
); }

my $deparse = B::Deparse->new;
$deparse->ambient_pragmas(strict => "all", warnings => "all");
sub canon_code($) {
	my($s) = @_;
	$s =~ s/[ \t\n]//g;
	$s =~ s#\{BEGIN\{(?:\$\^H\{'[a-z/]+'\}=undef;)*\}#{#;
	return $s;
}
sub depok($$) {
	is canon_code($deparse->coderef2text($_[0])), $_[1];
}

my($a0, $a1, $a2, $a3);
depok sub { 1 + is_shash($a0) },
	"{1+Hash::SharedMem::is_shash(\$a0);}";
depok sub { check_shash($a1); 123 },
	"{Hash::SharedMem::check_shash(\$a1);123;}";
depok sub { shash_open($a0, (rand($a1), $a2)) },
	"{Hash::SharedMem::shash_open(\$a0,(rand\$a1,\$a2));}";
depok sub { shash_is_readable($a0) + 1 },
	"{Hash::SharedMem::shash_is_readable(\$a0)+1;}";
depok sub { shash_is_writable($a3) },
	"{Hash::SharedMem::shash_is_writable(\$a3);}";
depok sub { shash_mode($a0) },
	"{Hash::SharedMem::shash_mode(\$a0);}";
depok sub { shash_getd($a0, $a1 = 123) },
	"{Hash::SharedMem::shash_getd(\$a0,\$a1=123);}";
depok sub { shash_get($a0, $a1 && $a2) },
	"{Hash::SharedMem::shash_get(\$a0,\$a1&&\$a2);}";
depok sub { shash_set($a0, $a1, $a2) },
	"{Hash::SharedMem::shash_set(\$a0,\$a1,\$a2);}";
depok sub { shash_gset($a0, $a1, $a2) },
	"{Hash::SharedMem::shash_gset(\$a0,\$a1,\$a2);}";
depok sub { shash_cset($a0, $a1, $a2, $a3) },
	"{Hash::SharedMem::shash_cset(\$a0,\$a1,\$a2,\$a3);}";
depok sub { shash_snapshot($a0) },
	"{Hash::SharedMem::shash_snapshot(\$a0);}";
depok sub { shash_is_snapshot($a0) },
	"{Hash::SharedMem::shash_is_snapshot(\$a0);}";

1;
