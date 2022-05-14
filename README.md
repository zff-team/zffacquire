# zffacquire

```zffacquire``` is a command line utility for acquiring images and/or logical file/folder structures into the forensic format Zff.

# Installation

## Prerequisites
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
Or you can install the tool directly from crates.io:
```bash
$ cargo install zffacquire
```

# Usage

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
