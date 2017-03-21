# jeb-plugins<sup>Stop Updating</sup>


## JumpTo[Ctrl+Shift+J]

From manifest view jump to the corresponding code.

## Decode[Ctrl+Shift+D]

Auto decode the encrypted strings.

1. Add `-Djava.ext.dirs=./lib` to the start scrit, so jeb could load the jars.
```
%JAVA% -Xmx2048m -XX:-UseParallelGC -XX:MinHeapFreeRatio=15 -Dfile.encoding=UTF-8 -Djava.ext.dirs=./lib -jar %DECOMPILER% %*
```
2. Decompile the dex file to jar file, then copy it to `./lib`.

3. Open the apk.

4. Ctrl+Shift+D.

## Rename[Ctrl+Shift+R]

renames classes/fields/methods from non-latin names to easier to read names


---

This repository will not be updated, because now I use JEB2.
