somethimes need unusual things, say when i debug web sign in, which show UI in `ZBID_LOCK` band i was need debugger run in `ZBID_ABOVELOCK_UX`
for create window in band we need call `CreateWindowInBand[Ex]`. but this will work not from any process.
but from explorer.exe will be work.
so i write some tool, for execute exe inside explorer (yes, exe, not dll) and also auto replace `CreateWindowExW` call to `CreateWindowInBand`

https://github.com/rbmm/Hollowed-Process/tree/main/x64/Release

need run 

```
StartInBand.exe *path to exe*[cmd line]
```

say start.bat exec notepad2.exe for demo

[StartInBand](https://github.com/rbmm/Hollowed-Process/tree/main/StartInBand)

exec exe inside explorer

and 

[MoveToBand](https://github.com/rbmm/Hollowed-Process/tree/main/MoveToBand)

by hooking `CreateWindowExW` replace it to `CreateWindowInBand`