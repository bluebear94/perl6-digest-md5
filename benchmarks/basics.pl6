use v6;
use lib './lib';
use Digest::MD5;

sub MAIN(int $iters = 100) {
  my $d = Digest::MD5.new;
  my $st = now;
  loop (my int $i = 0; $i < $iters; $i = $i + 1) {
    $d.md5_hex("Test " ~ $i);
  }
  my $diff = now - $st;
  say "Hashes per second: ", $iters / $diff;
}
