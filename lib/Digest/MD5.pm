#
# Digest::MD5 Perl6 module
#

class Digest::MD5:auth<cosimo>:ver<0.05> {
    constant \mask = 2 ** 32 - 1;
    sub prefix:<¬>(int \x) returns int       {   +^ x }
    sub infix:<⊞>(int \x, int \y) returns int    {  (x + y) +& mask }
    sub infix:«<<<»(int \x, int \n) returns int  { (x +< n) +| (x +> (32-n)) }

    constant \FGHI = -> \X, \Y, \Z { (X +& Y) +| (+^ X +& Z) },
               -> \X, \Y, \Z { (X +& Z) +| (Y +& +^ Z) },
               -> \X, \Y, \Z { X +^ Y +^ Z           },
               -> \X, \Y, \Z { Y +^ (X +| +^ Z)        };

    constant \S = (
            (7, 12, 17, 22) xx 4,
            (5,  9, 14, 20) xx 4,
            (4, 11, 16, 23) xx 4,
            (6, 10, 15, 21) xx 4,
        ).flat;


    constant \T = (floor(abs(sin($_ + 1)) * 2**32) for ^64).flat;

    constant \k = (
            (   $_           for ^16),
            ((5*$_ + 1) % 16 for ^16),
            ((3*$_ + 5) % 16 for ^16),
            ((7*$_    ) % 16 for ^16),
        ).flat;


    sub little-endian(int $w, int $n, *@v) {
      (@v X+> flat ($w X* ^$n)) X+& ((1 +< $w) - 1)
    }

    sub md5-pad($msg) {
        my \bits = $msg.elems +< 3;
        my @padded = flat $msg.list, 0x80, 0x00 xx (-((bits +> 3) + 9) +& 63);
        flat @padded.map({ ($^d +< 24) + ($^c +< 16) + ($^b +< 8) + $^a }), little-endian(32, 2, bits);
    }

    sub md5-block(int @H, int @X, $start) {
        my int ($A, $B, $C, $D) = @H;
        loop (my int $i = 0; $i < 64; $i = $i + 1) {
            my \f = FGHI[$i +> 4]($B, $C, $D);
            my $oldA = $A;
            $A = $D;
            $D = $C;
            $C = $B;
            $B = $B ⊞ ((($oldA + f + T[$i] + @X[k[$i] + $start]) +& mask) <<< S[$i]);
        }
        @H «⊞=» ($A, $B, $C, $D);
    }

    our sub md5($msg) {
        my int @M = md5-pad($msg);
        my int @H = Array.new(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
        my $iters = +@M;
        loop (my int $i = 0; $i < $iters; $i = $i + 16) {
          md5-block(@H, @M, $i);
        }
        Buf.new: little-endian(8, 4, @H)
    }

    multi method md5_hex(Str $str) {
        md5( $str.encode('latin-1') ).list».fmt('%02x').join
    }

    multi method md5_hex(@str) {
        md5( @str.join.encode('latin-1') ).list».fmt('%02x').join
    }

    multi method md5_buf(Str $str --> Buf) {
        md5( $str.encode('latin-1') );
    }

    multi method md5_buf(@str --> Buf) {
        md5( @str.join.encode('latin-1') );
    }
    INIT { say "TEST VERSION!"; }
}
