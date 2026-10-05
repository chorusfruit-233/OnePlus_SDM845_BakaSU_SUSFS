### AnyKernel3 Ramdisk Mod Script
## OnePlus 6/6T BakaSU + SUSFS

properties() { '
kernel.string=OnePlus SDM845 BakaSU + SUSFS
do.devicecheck=1
do.modules=0
do.systemless=1
do.cleanup=1
do.cleanuponabort=0
device.name1=enchilada
device.name2=fajita
device.name3=OnePlus6
device.name4=OnePlus6T
supported.versions=15
supported.patchlevels=
supported.vendorpatchlevels=
'; }

boot_attributes() {
set_perm_recursive 0 0 755 644 $RAMDISK/*;
set_perm_recursive 0 0 750 750 $RAMDISK/init* $RAMDISK/sbin;
}

BLOCK=boot;
IS_SLOT_DEVICE=1;
RAMDISK_COMPRESSION=auto;
PATCH_VBMETA_FLAG=auto;

. tools/ak3-core.sh;

dump_boot;
write_boot;
