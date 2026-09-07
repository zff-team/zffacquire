# zffacquire

```zffacquire``` is a command line utility for acquiring images, memory dumps and/or logical file/folder structures into the forensic format Zff.

This repository contains three crates:

| Crate | What it is |
| --- | --- |
| ```zffacquire``` | the command line tool |
| ```zffacquire-gui``` | a graphical front end for physical, logical and convert acquisitions |
| ```zffacquire-common``` | the acquisition logic both of them share |

# Installation

## Build from source (Linux)

### Prerequisites
First, you need to [install rust and cargo](https://rustup.rs/) to build or install ```zffacquire```.

After that you still need the gcc, which you can install as follows (depends on the distribution):
###### Debian/Ubuntu
```bash
$ sudo apt-get install gcc pkg-config libacl1-dev libudev-dev
```
###### Fedora
```bash
$ sudo dnf install gcc pkg-config libacl-devel systemd-devel
```

Then you can easily build this tool yourself by using cargo:
```bash
[/home/ph0llux/projects/zffacquire] $ cargo build --release -p zffacquire
```

Building ```zffacquire-gui``` additionally needs the development packages of the
graphics stack (on Debian/Ubuntu: ```libxkbcommon-dev libwayland-dev libx11-dev
libxcursor-dev libxi-dev libxrandr-dev```):
```bash
[/home/ph0llux/projects/zffacquire] $ cargo build --release -p zffacquire-gui
```

#### Cross-compile for Windows
Use the target ```x86_64-pc-windows-gnu``` for Windows x86 or ```aarch64-pc-windows-msvc``` for Windows on arm64.
Stable Rust is sufficient; the nightly compiler earlier versions asked for is no longer needed.

```bash
cargo build --release --target=x86_64-pc-windows-gnu # for x86 targets
cargo build --release --target=aarch64-pc-windows-msvc # for arm64 targets
```

## Install via cargo

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

If the container to extend consists of more than one segment, pass all of its
segment files to ```-a```. The new data is appended to the last segment, and the
container is only complete once every segment is kept together:
```bash
zffacquire extend physical -i /dev/sdb -a my_container.z01 my_container.z02 my_container.z03
```

The complete feature set of ```zffacquire``` can be shown using ```zffacquire -h```.

## Encryption

```-p``` prompts for the password interactively. For an unattended acquisition,
```--password-file``` reads it from a file instead (or from standard input, with
```-```); only the first line is used:
```bash
zffacquire physical -i /dev/sda -o my_container -p --password-file /run/secrets/case-password
```

Note that ```-n/--notes``` and ```-D/--description-notes``` are two different
fields: the first describes the acquired object, the second the container as a
whole. Setting one does not affect the other.

## Signing

With ```-S``` and no ```-k```, a signature key pair is generated for the
acquisition. The private key is printed **once**, as a warning, at the start of
the run: it is not stored in the container and cannot be recovered from it, so
capture it then or the signatures cannot be verified later.

## Converting other formats

An EWF image or a tar archive can be converted into a zff container:
```bash
zffacquire convert ewf -i evidence.E01 evidence.E02 -o my_zff_container
zffacquire convert tar -i archive.tar.zst -o my_zff_container
```

## Memory acquisition (Linux)

```bash
zffacquire memory -o /media/usb-hdd/my_memory_dump
```

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
zffacquire physical -i "\\?\HarddiskVolume2" -o my_volume_d
```

The NT object path form is accepted as well, so what ```mountvol``` prints can be
used directly:
```bash
zffacquire physical -i "\Device\HarddiskVolume2" -o my_volume_d
```

In both cases, you have to use the quotation marks as shown or to escape the \\ characters.

The complete feature set of ```zffacquire``` can be shown using ```zffacquire -h```.

# Sizes

Every size option (```-C/--chunk-size```, ```-M/--chunkmap-size```,
```-s/--segment-size```) is binary: ```K``` is 1024 bytes, ```M``` is 1024 KiB
and so on. ```K```, ```KB``` and ```KiB``` are accepted and mean the same thing.
Sizes the tool prints use the same base, so a size it reports parses back to
itself.

# The graphical front end

```zffacquire-gui``` covers physical, logical and convert acquisitions. Memory
acquisition and extending an existing container are available in the command
line tool only.

### Linux release builds

The CLI can be linked statically against musl, including libudev and POSIX ACL
support. The GUI is built separately for GNU/Linux because its desktop and
graphics backends use shared libraries.

`build-support/prepare-musl-sysroot.sh` provisions `/opt/zffacquire-musl` inside a
builder or disposable CI runner. It verifies a pinned Alpine root filesystem by
SHA-256, then uses Alpine's signed packages for the musl development libraries.
The packages come from the [official Alpine repository](https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/).
Do not install this sysroot on the acquisition machine.

For the local `noble` builder, run:

```sh
sudo systemd-run -M noble --wait --pipe /bin/bash "$PWD/build-support/prepare-musl-sysroot.sh"
./.scripts/install-builder-dropins.sh
./.scripts/build_and_release.sh --release
```

The project drop-in runs `build-support/release-in-builder.sh` inside the existing
unprivileged, offline build sandbox. It produces the static CLI under
`x86_64-unknown-linux-musl/release/` and the GUI under
`x86_64-unknown-linux-gnu/release/` in the builder's target directory. A CLI with
an ELF interpreter or shared-library dependencies fails the release check.
The x86_64 Linux release workflow provisions the same sysroot and checks linkage.

### GUI memory and extension

Choose **Memory** to acquire live RAM on Linux through the same eBPF reader as the
CLI. Kernel memory access and eBPF privileges are required; setup failures appear
in the acquisition log. Memory acquisition is unavailable on other platforms.

Choose **Extend Container**, select **all** existing segments, and choose logical
files, a physical disk/image, or Linux memory as the new evidence source. Review
lists the selected segments before acquisition appends the new object. Encryption
and signing parameters apply to the new evidence. For encrypted additions,
deduplication stays within the new data; existing chunks may use a different key
and are not reused. Cancelling waits for the worker
to stop; an interrupted write may leave an incomplete container.
