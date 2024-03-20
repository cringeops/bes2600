# bes2600
If you are here, you know exactly why you are here.

## How to build?
1. Build the danctnix kernel with bes2600 enabled
2. Build the module
```
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -C ../linux-pinetab2 M=$PWD modules
```
3. Deliver the module to the tablet and load it
```
sudo modprobe --force-vermagic ./bes2600.ko
```
