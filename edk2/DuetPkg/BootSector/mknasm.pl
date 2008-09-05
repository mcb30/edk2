#!/usr/bin/perl -w

use strict;
use warnings;

my $next_local = 1;
my $endm;

while ( <> ) {
  # Strip carriage returns and newlines
  s/\r//g;
  chomp;
  # Fix up segment register references of the form "ds:[...]" => "[ds:...]"
  s/\b([cdefgs]s:)\[/\[$1/ig;
  # Fix up opsize modifiers of the form "byte ptr" => "byte"
  s/\b((byte|word|dword)\s+)ptr\b/$1/ig;
  # Remove "ASSUME ds:@code" lines
  s/^(\s*ASSUME\s+[ds]s:\@code\s*)$/;$1/;
  # Remove opsize modifiers for lgdt,lidt etc.
  s/\b([ls][gi]dt\s+)fword\s+ptr\s*/$1/i;
  # Change "public" to "GLOBAL"
  s/^(\s*)public(\s+)/$1GLOBAL$2/i;
  # Change "OR" to "|"
  s/\bOR\b/|/g;
  # Change "dup()" to "TIMES"
  s/(db\s+)(.+?)\s+dup\s*\((.+?)\)/times $2 $1$3/ig;
  # Replace "org" with equivalent "times xx db 0"
  s/\borg\s+(\S+)/times $1-(\$-\$\$) db 0/i;
  # CPU type directive
  s/\.([3456]86)p?/CPU $1/i;
  # Section directives
  s/(\.code)/SECTION .text/i;
  s/(\.data)/SECTION .data/i;
  s/(\.stack)/SECTION .stack/i;
  # Replace ".model" with equivalent "BITS xx"
  s/\.model\s+small/BITS 16/i;
  s/\.model\s+flat/BITS 32/i;
  # Replace local label declarations
  $next_local += 1 if s/^(\s*)\@\@:/$1.l${next_local}:/i;
  # Replace local label references
  s/\@b/".l".($next_local-1)/eig;
  s/\@f/".l".($next_local)/eig;
  # Remove "offset"
  s/\boffset\b//ig;
  # Add line continuations where necessary
  s/^([^;]*,\s*)$/$1\\/i;
  # "REPEAT" => "%rep"
  $endm = "\%endrep" if s/^\s*repeat\b/\%rep/i;
  # "xxx macro" => "%macro xxx"
  $endm = "\%endmacro" if s/\s*(\S+)\s+macro/\%macro $1 0/i;
  # "ENDM" => $endm
  s/\bendm\b/$endm/i if defined $endm;
  # "df 0" => "db 0,0,0,0,0,0"
  s/\bdf\s+0\b/db 0,0,0,0,0,0/i;


  print "$_\n";
}
