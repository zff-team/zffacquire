//! End-to-end checks that what zffacquire writes can actually be read back.
//!
//! These exercise the failure that unit tests cannot see: a container that is
//! produced without error, and is then rejected by every reader. Both bugs
//! these cover -- appending to the wrong segment of a multi-segment container,
//! and truncating a container while extending it -- produced a clean exit and
//! an unusable evidence file.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

use zff::io::zffreader::ZffReader;

fn zffacquire() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zffacquire"))
}

/// Every segment of the container based at `base`, in order.
fn segments(base: &Path) -> Vec<PathBuf> {
    let dir = base.parent().expect("container has a parent directory");
    let stem = base.file_stem().expect("container has a file stem");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("output directory is readable")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.file_stem() == Some(stem))
        .filter(|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.starts_with('z'))
        })
        .collect();
    paths.sort();
    paths
}

/// The object numbers a reader finds in the container, or the reason it could
/// not open it.
fn read_back(base: &Path) -> Result<Vec<u64>, String> {
    let paths = segments(base);
    assert!(!paths.is_empty(), "no segment was written for {}", base.display());
    let files: Vec<File> = paths
        .iter()
        .map(|p| File::open(p).unwrap_or_else(|e| panic!("cannot open {}: {e}", p.display())))
        .collect();
    let mut reader = ZffReader::with_reader(files).map_err(|e| e.to_string())?;
    reader.initialize_objects_all().map_err(|e| e.to_string())?;
    let mut objects: Vec<u64> = reader
        .list_objects()
        .map_err(|e| e.to_string())?
        .keys()
        .copied()
        .collect();
    objects.sort();
    Ok(objects)
}

fn input_image(dir: &Path, name: &str, size: usize) -> PathBuf {
    let path = dir.join(name);
    // Incompressible, so a segment size actually forces several segments
    // rather than the whole image collapsing into one.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let content: Vec<u8> = (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    std::fs::write(&path, content).expect("test input is writable");
    path
}

fn run(command: &mut Command) {
    let output = command.output().expect("zffacquire runs");
    assert!(
        output.status.success(),
        "zffacquire failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn physical_container_is_readable() {
    let dir = tempdir();
    let input = input_image(dir.path(), "disk.raw", 2 * 1024 * 1024);
    let out = dir.path().join("physical");

    run(zffacquire().args(["physical", "-i"]).arg(&input).arg("-o").arg(&out));

    assert_eq!(read_back(&out).expect("container is readable"), vec![1]);
}

#[test]
fn extending_a_single_segment_container_keeps_it_readable() {
    let dir = tempdir();
    let input = input_image(dir.path(), "disk.raw", 1024 * 1024);
    let out = dir.path().join("single");

    run(zffacquire().args(["physical", "-i"]).arg(&input).arg("-o").arg(&out));
    run(zffacquire()
        .args(["extend", "physical", "-i"])
        .arg(&input)
        .arg("-a")
        .arg(out.with_extension("z01")));

    assert_eq!(read_back(&out).expect("container is readable"), vec![1, 2]);
}

/// zff appends to the segment holding the main footer, which is the *last*
/// segment. Writing the appended bytes into the first segment instead produced
/// a container whose main footer no longer decoded.
#[test]
fn extending_a_multi_segment_container_keeps_it_readable() {
    let dir = tempdir();
    let input = input_image(dir.path(), "disk.raw", 5 * 1024 * 1024);
    let out = dir.path().join("multi");

    run(zffacquire()
        .args(["physical", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .args(["-s", "1M"]));

    let written = segments(&out);
    assert!(written.len() > 1, "expected several segments, got {written:?}");

    let mut extend = zffacquire();
    extend.args(["extend", "physical", "-i"]).arg(&input).arg("-a");
    for segment in &written {
        extend.arg(segment);
    }
    run(&mut extend);

    assert_eq!(read_back(&out).expect("container is readable"), vec![1, 2]);
}

/// The tar conversion writes a passive container and then extends it with a
/// virtual object. Recreating the output file for the second step truncated
/// the first step's work.
#[test]
fn converted_tar_container_is_readable() {
    let dir = tempdir();
    let content = dir.path().join("content");
    std::fs::create_dir(&content).expect("content directory is creatable");
    std::fs::write(content.join("a.txt"), b"hello").expect("test file is writable");
    std::fs::write(content.join("b.txt"), b"world").expect("test file is writable");

    let archive = dir.path().join("archive.tar");
    let status = Command::new("tar")
        .arg("cf")
        .arg(&archive)
        .arg("-C")
        .arg(dir.path())
        .arg("content")
        .status()
        .expect("tar runs");
    assert!(status.success(), "could not create the test archive");

    let out = dir.path().join("converted");
    run(zffacquire().args(["convert", "tar", "-i"]).arg(&archive).arg("-o").arg(&out));

    // The passive object carrying the archive, and the virtual object mapping it.
    assert_eq!(read_back(&out).expect("container is readable"), vec![1, 2]);
}

/// A directory that removes itself, so a failing test leaves nothing behind.
struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> TempDir {
    let path = std::env::temp_dir().join(format!(
        "zffacquire-test-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("temporary directory is creatable");
    TempDir(path)
}
