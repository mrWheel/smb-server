# Path safety test cases

The path resolver must accept normal SMB paths and reject attempts to leave the
configured share root.

Expected valid examples:

```text
file.txt
folder/file.txt
\folder\file.txt
/folder/file.txt
folder/./file.txt
```

Expected invalid examples:

```text
..
../secret
folder/../../secret
\..\secret
C:\secret
folder:C
```

Add Unity tests when the first hardware build is stable.
