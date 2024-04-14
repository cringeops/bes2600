# bes2600
If you are here, you know exactly why you are here.

## How to build?
### On the PineTab2 itself
0. Install the build tools and kernel headers, if not already done:
```
sudo pacman -S base-devel git linux-pinetab2-headers
```
1. Build the module
```
cd path/to/bes2600
make -C /lib/modules/$(uname -r)/build M=$PWD modules
```
2. Load the module
```
sudo modprobe ./bes2600/bes2600.ko
```

### On another machine
1. Build the danctnix kernel with bes2600 enabled
2. Build the module
```
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -C ../linux-pinetab2 M=$PWD modules
```
3. Deliver the module to the tablet and load it
```
sudo modprobe --force-vermagic ./bes2600.ko
```
## TODO list
1. ~~Get rid of all unnecessary code (usb/spi parts that we couldn't care less about)~~ [done](https://github.com/cringeops/bes2600/pull/2)
2. ~~Implement MAC setting the standard way via DT local-mac-address~~ [done, needs provided dtsi](https://github.com/cringeops/bes2600/pull/5)
3. ~~Use devm API for GPIO management~~ [done](https://github.com/cringeops/bes2600/pull/6)
4. ~~Solve the sleep issue (PT2 doesn't go into sleep if bes2600 module is loaded)~~ [done](https://github.com/cringeops/bes2600/pull/9)
5. Test power consumption and implement sleep mode for the chip
