# Dex file binary foot print analyzing tool
Introduction:
-------------
This tool is made to analyze binary foot print of a dex file (the classes.dex in apk file).

It works very much like a regular performance profiler.  

It calculates "cumluative binary size" and "self binary size" of every object [1] of a dex file to give you detailed information about how much the binary foot print it takes.  

(More information about how  "cumluative binary size" and "self binary size" are calculated is explained in the following sections.)

[1] An object in a dex file includes class, method, string etc, see here:
  https://source.android.com/devices/tech/dalvik/dex-format.html

in section "Type Codes"

How size is calculated:
----------------------

* **Cumulative size:**  
Cumulative size of an object is defined as the size of the object itself plus **"adjusted size"** of all the objects it references.

* **Self size:**  
The "size" of the object itself. 

* **Adjusted size:**  
As mentioned in the "cum size" seciton, the "cum size" is not calculated by summing up the "size" of all the referenced objects. It rather sums up the **"adjusted size"** which is defined as **(size of the object / the reference count of the object)**.  

The rationale is that the cum size of all the items of a dex file should add up to the size of the dex file in order to reflect how much binary space each item occupies. However in reality one object could be referenced by many objects, If we add the size of the object to every cum size of the objects that reference it, the cum size will not add up to the size of a dex file, because obviously these objects which have more than one reference would be counted multiple times. 

Therefore, we use adjusted size as mentioned above, to make sure the cum size of every item is fairly calculated.
 
In the report, all the values are rounded to integers.

FAQ:
------

According to https://www.python.org/dev/peps/pep-0394/, we use python2 as the name of python 2.x intepretor. Therefore if you see error like this:   

	env: python2: No such file or directory

The solution is here:   

	sudo ln -s /usr/bin/python2.7 /usr/bin/python2

If you are using Mac OS X El Capitan or later, its new System Integrity Protection feature prevents changes to several core parts of OS X, including most of /usr, even by root.

So the solution should be like this instead:

	sudo mkdir -p /usr/local/bin
	sudo ln -s /usr/bin/python2.7 /usr/local/bin/python2
	
See more details:
[https://stackoverflow.com/questions/36730549/cannot-create-a-symlink-inside-of-usr-bin-even-as-sudo]()

Usage:
------
It's recommended to use pypy http://pypy.org/ to get better performance.  The script needs to build up the reference grahics of all the items in the dex file, hence takes some time (30s+ sometimes). Python implementation with JIT, such like pyp, will significantly improve the speed.

	dex.py [-h] [-m MAP_PROGUARD] [-st] [-d] [-l] [-s] [-q] dexfile  

  	dexfile               dex file to analyze.  

	optional arguments:

	-h, --help            show this help message and exit.
	-m MAP_PROGUARD, --map-proguard MAP_PROGUARD
	                      map file to translate the symbol.
	-st, --size_stats     statistics about all the items.
	-d, --debug           debug information.
	-l, --list-report     output a list report in csv format.
	-s, --sort-by-self    sort the result by self size.
	-q, --quiet           quiet mode, run without progress information.

Sample Output:
--------------
	$ dex.py  testcases/classes-2.dex  -s -m testcases/classes-2.txt 
	Type         Cum.      Self      Content                                    Class
	Method       17499     7756      com.android.EventLogger$Name_<clinit>      com.android.EventLogger$Name
	Method       3371      3260      com.ibm.icu.text.CharsetRecog_<clinit>     com.ibm.icu.text.CharsetRecog
	Method       4863      3166      void preInitialization(java.lang.Object)   com.opera.android.OperaMainActivity
	Method       4981      2979      void onCreate()                            com.opera.android.OperaApplication
	Method       4144      2780      void moveToState(int,int,int,boolean)      android.support.v4.app.FragmentManagerImpl
	Method       4195      2649      void run()                                 com.android.browser.WebviewDownloadThread
	String:5765  2511      2511      acadaeafagaialamaawaxazbabbbebfbgbhbi      com.android.utilities.DomainValidator
