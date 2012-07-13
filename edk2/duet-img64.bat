GenFds -f DuetPkg\DuetPkg.fdf -o Z:\work\extcvs\efi\edk2\edk2\Build\DuetPkg\DEBUG_WINDDK3790x1830 -t WINDDK3790x1830 -b DEBUG -p Z:\work\extcvs\efi\edk2\edk2\DuetPkg\DuetPkg.dsc -a X64  -D "EFI_SOURCE=EdkCompatibilityPkg"  -D "EDK_SOURCE=EdkCompatibilityPkg"  -D "WORKSPACE="
cd DuetPkg
call PostBuild.bat X64
call CreateBootDisk64.bat floppy A: FAT12
cd ..
