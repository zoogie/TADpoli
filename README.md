# What is this?
A program that allows you to dump the contents of a DSi dsiware export, modify them, and rebuild to an importable .bin file.
# Requirements
* Windows 64bit - compiling to Linux & Mac should be easy given there are no dependancies here though
* A DSiWare export from your DSi console - they are found at sdmc:/private/ds/title/<here>. The filename must be in the format: <8 digit hex>.bin Ex. 484E4441.bin)
* (optional, needed for importing on > firm 1.4.1) A DECRYPTED `dev.kp` from your target console placed in the same dir as TADpoli.exe (see additional notes)

# Usage  
Basic Command Line usage is:
```
Dump (8-digit hex).bin to out/<sections.bin>:
TADpoli (8-digit hex).bin d
Rebuild from out/<sections.bin> to out/(8-digit hex).bin:
TADpoli (8-digit hex).bin r
```
You may also drag n drop the .bin on the .exe to dump the TAD's files to the out/ directory automatically.

# Additional Notes
* The dev.kp needs to be decrypted from its encrypted state when extracted from your nand at /sys/dev.kp. You may use [twltool](https://github.com/WinterMute/twltool/releases) to decrypt it.<br>
Check that repo for directions.
* The DSi is surprisingly less permissive than the 3ds when dealing with modified export (TAD) files. You can't inject random titles into different titles, for instance. You also can't inject to system titles.<br>
You can modify saves and even downgrade same titles to different versions, however.
* You need a decrypted dev.kp from YOUR console to import modified TADs, UNLESS, you are on firmware 1.4.1 or less, OR have a downgraded DSi system settings app (to whatever version 1.4.1 firm uses or less).
* It is not currently possible to obtain your dev.kp unless your system is already hacked (or hardmodded).
* Tech support questions will likely be ignored. There are many forums and discords out there that can provide that service.

# Greets
* **booto** for [sav-adjust](https://github.com/booto/dsi/tree/master/save_adjust) (most of TADpoli is based on it) 
* **neimod** for [taddy](https://github.com/booto/dsi/tree/master/taddy) (sav-adjust above imports significant code from this). Also, it's likely that the public dev.kp from dsibrew.org used here as a default cert, is his.
Check cert.c for more info.
* **caitsith2** for the special TMD/srl crypto DSi TADs use (get_contentkey func) [dsi_srl_extract](https://github.com/einstein95/dsi_srl_extract)

# Libraries used
 * [libsha1](https://github.com/dottedmag/libsha1)
