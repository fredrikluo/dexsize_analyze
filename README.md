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
<table style="border:0">
<tr><td>Type                </td><td>Cum.      </td><td>Self      </td><td>Content                                                     </td><td>Class</td></tr>
<tr><td>String:15041        </td><td>50524     </td><td>50524     </td><td>f0VMRgEBAQAAAAAAAAAAAAMAKAABAAAA6A4AADQAAAAIkQAAAg          </td><td>com.f.b.d.m</td></tr>
<tr><td>String:12433        </td><td>45174     </td><td>45174     </td><td>a&027qjf--nx?12oa08--nx?2eyh3la2ckx--nx?32wqq1--nx          </td><td>com.b.b.a.a</td></tr>
<tr><td>Method              </td><td>22007     </td><td>18804     </td><td>e                                                           </td><td>android.a.a.e</td></tr>
<tr><td>String:15040        </td><td>17668     </td><td>17668     </td><td>f0VMRgEBAQAAAAAAAAAAAAMAAwABAAAAkAYAADQAAADIMAAAAA          </td><td>com.f.b.d.m</td></tr>
<tr><td>Method              </td><td>16665     </td><td>7472      </td><td><clinit>                                                    </td><td>com.opera.android.statistic.EventLogger$Name</td></tr>
<tr><td>Encoded array       </td><td>5262      </td><td>5262      </td><td>                                                            </td><td>com.opera.android.R$string</td></tr>
<tr><td>Encoded array       </td><td>5252      </td><td>5252      </td><td>                                                            </td><td>com.opera.android.R$id</td></tr>
<tr><td>Encoded array       </td><td>5112      </td><td>5112      </td><td>                                                            </td><td>com.opera.android.R$drawable</td></tr>
<tr><td>Method              </td><td>3340      </td><td>3335      </td><td><clinit>                                                    </td><td>a.a.b.b.d</td></tr>
<tr><td>Method              </td><td>3373      </td><td>3260      </td><td><clinit>                                                    </td><td>com.c.a.a.x</td></tr>
<tr><td>Method              </td><td>3747      </td><td>3232      </td><td>onDraw                                                      </td><td>com.opera.android.TabContainer</td></tr>
</table>
...

Very self explanatory.


 
