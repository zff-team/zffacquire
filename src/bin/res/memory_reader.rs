// - Parents
use super::*;

//TODO: implement an alternative way here (e.g. by using AVML?)
pub(crate) enum MemoryReaderType {
    Emd
}

#[derive(Default)]
struct InnerRangePosition {
    pub current_range: u64,
    pub offset: u64,
}

pub struct Emd {
    ebpf: Ebpf,
    page_offset_base: u64,
    system_ram_ranges: Vec<Range<u64>>,
    inner_range_position: InnerRangePosition,
    internal_buffer: Cursor<Vec<u8>>,
    remaining_buffer: usize,
}

impl Emd {
    pub fn new() -> Result<Self> {
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime.
        debug!("Load eBPF program.");
        let mut ebpf = Ebpf::load(emd_ebpf::EBPF_BINARY)?;
        debug!("Initialize read_kernel_memory function.");
        let program: &mut UProbe = ebpf.program_mut(READ_KERNEL_MEM).unwrap().try_into()?;
        program.load()?;

        let fn_addr = read_kernel_memory as *const () as usize;
        let offset = (fn_addr - get_base_addr()?) as u64;

        debug!("Attaching program on {PROC_SELF_EXE}.");
        program.attach(None, offset, PROC_SELF_EXE, None)?;

        debug!("Initializing buffer queue.");
        let mut buffer_queue = Queue::try_from(ebpf.map_mut("BUFFER_QUEUE").unwrap())?;

        let page_offset_base = get_page_offset_base(&mut buffer_queue)?;
        let system_ram_ranges = extract_mem_range(SEPARATOR_SYSTEM_RAM)?;
        let mut inner_range_position = InnerRangePosition::default();

        // fills the internal buffer initially.
        let internal_buffer = get_next_buffer_value(
            &mut buffer_queue,
            &system_ram_ranges,
            &mut inner_range_position,
            page_offset_base
        );

        let remaining_buffer = internal_buffer.len();

        Ok(Self {
            ebpf,
            page_offset_base,
            system_ram_ranges,
            inner_range_position,
            internal_buffer: Cursor::new(internal_buffer),
            remaining_buffer,
        })
    }

    fn fill_buffer(&mut self) {
        let mut buffer_queue = Queue::try_from(self.ebpf.map_mut("BUFFER_QUEUE").unwrap()).unwrap();
        let internal_buffer = get_next_buffer_value(
            &mut buffer_queue,
            &self.system_ram_ranges,
            &mut self.inner_range_position,
            self.page_offset_base
        );
        self.internal_buffer = Cursor::new(internal_buffer);
    }
}

impl Read for Emd {
    // Reads the kernel memory
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut total_read = 0;

        while total_read < buf.len() {
            if self.remaining_buffer > 0 {
                let read_size = self.remaining_buffer.min(buf[total_read..].len());
                self.internal_buffer.read(&mut buf[total_read..])?;
                self.remaining_buffer -= read_size;
                total_read += read_size;
            }

            // re-fill buffer
            if self.remaining_buffer == 0 {
                self.fill_buffer();
                self.remaining_buffer = self.internal_buffer.get_ref().len();

                // check if the end of the memory ranges was reached
                if self.remaining_buffer == 0 {
                    return Ok(total_read);
                }
            }
        }

        Ok(total_read)
    }
}

fn get_next_buffer_value(
    buffer_queue: &mut Queue<&mut MapData, [u8; BUFFER_SIZE]>,
    system_ram_range: &Vec<Range<u64>>, 
    inner_range_position: &mut InnerRangePosition,
    mapping_offset: u64,
    ) -> Vec<u8> {
        let mut remaining = MAX_QUEUE_SIZE;
        let mut buffer = Vec::new();

        while remaining > 0 {
            let range = match system_ram_range.iter().nth(inner_range_position.current_range as usize) {
                Some(range) => range,
                None => return buffer,
            };

            // Compute available bytes in current range
            let position_offset = range.start + inner_range_position.offset;
            let available = (range.end - position_offset) as usize;
            let dump_size = available.min(remaining);

            if dump_size == 0 {
                inner_range_position.current_range += 1;
                inner_range_position.offset = 0;
                continue;
            }
            
            let mut lime_header = LimeHeader::default();
            lime_header.start_address = position_offset;
            lime_header.end_address = position_offset + dump_size as u64;
            buffer.extend(lime_header.as_bytes());

            read_kernel_memory(mapping_offset+position_offset, dump_size);
            let queue_elements = calc_queue_elements(dump_size);
            let mut unreadable_offsets = None;
            for i in 0..queue_elements {
                let queue_element_size = if i == queue_elements && dump_size % BUFFER_SIZE != 0 {
                    dump_size % BUFFER_SIZE
                } else {
                    BUFFER_SIZE
                };
                let inner_buffer = match buffer_queue.pop(0) {
                    Ok(value) => value,
                    Err(_) => {
                        if unreadable_offsets.is_none() {
                            unreadable_offsets = Some((position_offset, i));
                        }
                        [0u8; BUFFER_SIZE]
                    }
                };
                buffer.extend(&inner_buffer[..queue_element_size]);
            }

            if let Some((offset, i)) = unreadable_offsets {
                // only necessary to print in warning.
                let start_offset = offset + (BUFFER_SIZE * i) as u64;
                let end_offset = offset + (BUFFER_SIZE * (queue_elements-1)) as u64;
                debug!("Could not read 0x{start_offset:x} - 0x{end_offset:x}. Writing zeros for appropriate zone.");
            }
            
            inner_range_position.offset += dump_size as u64;
            remaining -= dump_size;

            // Move to the next range if we have consumed the current one
            if inner_range_position.offset + range.start >= range.end {
                inner_range_position.current_range += 1;
                inner_range_position.offset = 0;
            }
        }

        buffer
    }

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn _read_kernel_memory(_src_address: u64, _dump_size: usize) {}

#[unsafe(no_mangle)]
#[inline(never)]
fn read_kernel_memory(offset: u64, dump_size: usize) {
    let func: extern "C" fn(u64, usize) = _read_kernel_memory;
    // unsafe block is necessary to ensure the compiler will not optimize this away.
    unsafe {
        std::ptr::read_volatile(&func);
        func(offset, dump_size);
    }
}

pub(crate) fn memory_size() -> Result<u64> {
    let memory_ranges = extract_mem_range(SEPARATOR_SYSTEM_RAM)?;
    let mut total_size = 0;
    for range in memory_ranges {
        total_size += range.end - range.start;
    }
    Ok(total_size)
}

fn get_page_offset_base(buffer_queue: &mut Queue<&mut MapData, [u8; BUFFER_SIZE]>) -> Result<u64>{
    let page_offset_base_addr = get_page_offset_base_address_from_file()?;
    read_kernel_memory(page_offset_base_addr, 8);
    let slice: &[u8] = &buffer_queue.pop(0)?[..8];
    Ok(u64::from_le_bytes(slice.try_into()?))
}

fn get_base_addr() -> Result<usize> {
    let me = Process::myself()?;
    let maps = me.maps()?;

    for entry in maps {
        if entry.perms.contains(MMPermissions::EXECUTE) && 
        entry.perms.contains(MMPermissions::READ) && 
        entry.perms.contains(MMPermissions::PRIVATE) {
            return Ok((entry.address.0 - entry.offset) as usize);
        }
    }
    
    error!("Failed to find executable region");
    exit(EXIT_STATUS_ERROR);
}