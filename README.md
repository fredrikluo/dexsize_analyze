# Dex file binary foot print analyzing tool 
Introduction:
-------------

Run this tool to profile binary foot print of all the items that comprise
a .dex file (classes.dex in apk file).

It works like a performance profiler in many ways - it calculate both
self and cumulative binary foot print of each item in dex file, including:
class, method, string etc.

How size is calculated:
----------------------

Cumulative size (Cum. size): Cumulative size of an object is the size of the
object itself + the adjusted[1] size of all the objects which are referenced.

Self size: The adjusted size of the object itself.

[1] adjusted size:
In a dex file, an objects could be referenced by many objects. Therefore, if
we use the actual size of the object for every objects which references it,
the result would be inaccurate and can't reflect how much "real" space the 
object is taking.

For example:

Suppose a string S "abc", it takes 3 bytes in UTF-8 format. And if there are
class A, class B, both referencing the string C. String C actually contributes
binary foot print to both class A and B, therefore, we say, the ""adjusted size"
of string S is 3/2 = 1.5 bytes.

In the report. All the values are rounded to integers.

Usage:
------

dex.py [-h] [-l] [-s] [-q] dexfile

positional arguments:
  dexfile             dex file to analyze.

optional arguments:
  -h, --help          show this help message and exit
  -l, --list-report   output a list report with item-id:size.
  -s, --sort-by-self  sort the result by self size.
  -q, --quiet         quiet mode, run without progress information.

A sample output:
----------------
<code>
Type                Cum.      Self      Content         Class
String:15041        50524     50524     f0VMRgEBAQA     com.f.b.d.m
String:12433        45174     45174     a&027qjf--n     com.b.b.a.a
Method              22007     18804     e               android.a.a.e
String:15040        17668     17668     f0VMRgEBAQA     com.f.b.d.m
Method              16665     7472      <clinit>        com.opera.android.statistic.EventLogger$Name
Encoded array       5262      5262                      com.opera.android.R$string
Encoded array       5252      5252                      com.opera.android.R$id
Encoded array       5112      5112                      com.opera.android.R$drawable
Method              3340      3335      <clinit>        a.a.b.b.d
Method              3373      3260      <clinit>        com.c.a.a.x
</code>
...

Very self explanatory.


 
