# Dex file binary foot print analyzing tool
Introduction:
-------------
This tool is made to analyze binary foot print of a dex file (the classes.dex in apk file).

It works very much like a regular performance profiler:  
It calculates "cumluative binary size" and also the "self binary size" of a item [1] in a dex file to give you detailed information about how the binary foot print of a dex file is composed.  
(More information about how  "cumluative binary size" and "self binary size" are calculated will be explained in the following sections.)

[1] An Item in a dex file includes class, method, string etc.

How size is calculated:
----------------------

* **Cumulative size:**  
Cumulative size of an object is the size of the object itself plus **"adjusted size"** of all the objects it referers.
* #### Self size:
The "size" of the object itself. 

* **Adjusted size:**
As mentioned in the "cum size" seciton, the "cum size" is not calculated by summing up the "self size" of all the referenced objects. It rather sums up the **"adjusted size"** which is defined as **(size of the object / the reference count of the object)**.  
The rationale behind this is that in a dex file, an objects could be referenced by many
objects. If we add the size of the object up to the cum. size of all the objects that reference it, these cum size would look very misguiding.  
For example, there are 5 objects referencing a resource string which is 5k bytes in binary foot print.  If you take raw foot print of resource string , cum size of each of the 5 referencing objects will be a least 5k bytes, and it's not really what happened. It's better to say,  every object in this 5 objects shares the resouce string, hence only take 1/5 of the resource stirng's foot print. Therefore, let's say the adjusted size of a this resource string is 1/5 * 5K = 1K.  
In the report, all the values are rounded to integers.

Usage:
------
It's recommended to use pypy http://pypy.org/ to get better performance.  The script needs to build up the reference grahics of all the items in the dex file, hence takes some time (30s+ sometimes). Python implementation with JIT, such like pyp, will significantly improve the speed.

dex.py [-h] [-m MAP_PROGUARD] [-st] [-d] [-l] [-s] [-q] dexfile  

  dexfile               dex file to analyze.  

optional arguments:  
  -h, --help            show this help message and exit  
  -m MAP_PROGUARD, --map-proguard MAP_PROGUARD  
                        map file to translate the symbol.  
  -st, --size_stats     statistics about all the items.  
  -d, --debug           debug information.  
  -l, --list-report     output a list report in csv format.  
  -s, --sort-by-self    sort the result by self size.  
  -q, --quiet           quiet mode, run without progress information.  

