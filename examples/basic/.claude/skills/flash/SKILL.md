---
name: flash
description: Build and flash the ESP32 target safely
---
1. Read projectPrompt.md and codingRules.md first.
2. cd to examples/basic
3. Run `echo $IDF_TARGET` and `cat sdkconfig | grep IDF_TARGET` and report any mismatch BEFORE building.
4. If they differ, run `idf.py set-target <correct>` and `idf.py fullclean`.
5. Run `idf.py build` and stop on first error; report the exact error, do not guess fixes.
6. On success: `idf.py -p $PORT flash monitor`.
