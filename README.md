# zffacquire

```zffacquire``` is a command line utility for acquiring images and/or logical file/folder structures into the forensic format Zff.

# Installation

## Build from source (Linux)

### Prerequisites
First, you need to [install rust and cargo](https://rustup.rs/) to build or install ```zffacquire```.

After that you still need the gcc, which you can install as follows (depends on the distribution):
###### Debian/Ubuntu
```bash
$ sudo apt-get install gcc
```
###### Fedora
```bash
$ sudo dnf install gcc
```

Then you can easily build this tool yourself by using cargo:
```bash
[/home/ph0llux/projects/zffacquire] $ cargo build --release
```

#### Cross-compile for Windows
You need a cross-compiler and should use the target ```x86_64-pc-windows-gnu``` for Windows x86 or ```aarch64-pc-windows-msvc``` for Windows on arm64.  
It is necessary to use a nightly compiler, stable Rust is currently not supported for Windows targets (by the underlying zff-library).  

```bash
cargo +nightly build --release --target=x86_64-pc-windows-gnu # for x86 targets
cargo +nightly build --release --target=aarch64-pc-windows-msvc # for arm64 targets
```

## Install via cargo

```
Or you can install the tool directly from crates.io:
```bash
$ cargo install zffacquire
```

# Usage

## Example for Linux systems

To create an image with the default parameters, the following command is just enough:
```bash
zffacquire physical -i /dev/sda -o /media/usb-hdd/my_zff_container
```

You can also dump a logical folder structure into a logical zff container:
```bash
zffacquire logical -i /home/ph0llux/pictures -o /media/usb-hdd/my_zff_container
```

And you can extend an zff container by adding additional containers:
```bash
zffacquire physical -i /dev/sda -o /media/usb-hdd/my_zff_container
zffacquire extend logical -i /home/ph0llux/pictures -a /media/usb-hdd/my_zff_container.z01
zffacquire extend physical -i /dev/sdb -a /media/usb-hdd/my_zff_container.z01
```

The complete feature set of ```zffacquire``` can be shown using ```zffacquire -h```.

## Example for Windows systems

On Windows, you can list the dumpable physical targets with the ```list-devices``` subcommand.  
```bash
zffacquire list-devices
```

If you want to dump a full physical device, you can choose the appropriate device from the printed table (by using the command above).  
```bash
zffacquire physical -i "\\?\PhysicalDrive2" -o my_physical_drive
```

You can also dump just a single volume (e.g. the volume which is mounted at drive D:\\):
```bash
zffacquire physical -i "\Device\HarddriveVolume2" -o my_volume_d
```

In both cases, you have to use the quotation marks as shown or to escape the \\ characters.

The complete feature set of ```zffacquire``` can be shown using ```zffacquire -h```.
