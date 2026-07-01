//! Parsed-binary model: ELF / PE / Mach-O, with `vaddr <-> file offset`
//! translation and size-aware readers.
//!
//! The model is intentionally narrow: it exposes only what analyzers need
//! (`Section`s, `Symbol`s, byte reads by virtual address, target architecture
//! bitness). Anything richer (full disassembly, relocation processing) is
//! deliberately out of scope — `rustrip` reasons about *data*, not control
//! flow, in v0.1.

use anyhow::{anyhow, Context, Result};
use goblin::{elf, mach, pe, Object};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    /// Raw section bytes (may be shorter than `size` if the on-disk segment
    /// is truncated; never longer).
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub vaddr: u64,
    pub name: String,
    pub size: u64,
}

/// In-memory parsed object representing a single executable format.
///
/// File bytes are kept so that vaddrs can be resolved even if sections were
/// truncated on disk (NOBITS, sparse Mach-O, etc.) — readers return `None`
/// rather than panic when ranges fall outside the loaded segment.
pub struct Binary {
    pub path: Option<String>,
    pub format: BinaryFormat,
    pub arch: String,
    /// `true` for 64-bit objects, `false` for 32-bit. Analyzers size their
    /// pointer reads off this flag.
    pub is_64: bool,
    pub little_endian: bool,
    pub bytes: Vec<u8>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,

    /// Sorted by vaddr for binary-search lookup: `(vaddr_begin, vaddr_end_exclusive, section_index)`
    /// where the address range covered is `[begin, end)`.
    sec_by_vaddr: Vec<(u64, u64, usize)>,
    /// Indices into `sections` of sections we believe may host string bytes.
    string_sections: Vec<usize>,
}

impl Binary {
    /// Parse a raw object file (ELF, PE, or single-arch Mach-O).
    ///
    /// The input is cloned once internally so that the parsed object's
    /// `&[u8]` references (via `Elf<'_>`, `PE<'_>`, `Mach<'_>`) stay valid
    /// until we finish copying them out into owned types.
    ///
    /// # Errors
    ///
    /// Returns `Err` when goblin cannot recognize the format, when the
    /// object is truncated, when an ar archive is passed (we do not
    /// dereference archive members in v0.1), or when a Mach-O fat archive
    /// is passed (we only support single-arch slices).
    pub fn parse(path: Option<&str>, bytes: Vec<u8>) -> Result<Self> {
        let parse_buffer = bytes.clone();
        let obj = Object::parse(&parse_buffer).context("goblin: failed to parse object")?;
        match obj {
            Object::Elf(elf) => load_elf(path, &elf, bytes),
            Object::PE(pe) => load_pe(path, &pe, bytes),
            Object::Mach(mach) => load_mach(path, &mach, bytes),
            _ => Err(anyhow!("unsupported object kind (likely archive)")),
        }
    }

    /// Translate `vaddr` to `(section_index, offset_within_section)`. Returns
    /// `None` if `vaddr` falls outside the span of any loaded section.
    ///
    /// # Panics
    ///
    /// Panics if `(vaddr - section_start)` does not fit in `usize` — only
    /// possible on platforms with 32-bit pointers where the section rises
    /// above `usize::MAX` bytes. We do not support building on such a host.
    #[must_use]
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<(usize, usize)> {
        let idx = self.sec_by_vaddr.binary_search_by(|(start, end, _)| {
            if vaddr < *start {
                std::cmp::Ordering::Greater
            } else if vaddr >= *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        });
        idx.ok().map(|i| {
            let (start, _end, sec_i) = self.sec_by_vaddr[i];
            let off_in_sec = usize::try_from(vaddr - start)
                .expect("vaddr-to-offset: offset within section fits usize on supported targets");
            (sec_i, off_in_sec)
        })
    }

    /// Read `len` bytes at `vaddr`. Returns `None` if any byte falls
    /// outside the section bounds or the backing `data` is too short.
    #[must_use]
    pub fn read_at_vaddr(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        let (sec_i, off) = self.vaddr_to_offset(vaddr)?;
        let sec = &self.sections[sec_i];
        if off.checked_add(len)? > sec.data.len() {
            return None;
        }
        Some(&sec.data[off..off + len])
    }

    /// Read a pointer-sized value (4 bytes on 32-bit, 8 on 64-bit) at
    /// `vaddr`, respecting the binary's endianness.
    #[must_use]
    pub fn read_ptr(&self, vaddr: u64) -> Option<u64> {
        let sz = if self.is_64 { 8 } else { 4 };
        let bytes = self.read_at_vaddr(vaddr, sz)?;
        Some(if self.little_endian {
            read_le_ptr(bytes, self.is_64)
        } else {
            read_be_ptr(bytes, self.is_64)
        })
    }

    /// Read a u32 (little- or big-endian per `self.little_endian`).
    #[must_use]
    pub fn read_u32(&self, vaddr: u64) -> Option<u32> {
        let bytes = self.read_at_vaddr(vaddr, 4)?;
        Some(if self.little_endian {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        })
    }

    /// `true` if `vaddr..vaddr+len` lies entirely inside a section
    /// classified as hosting string bytes (read-only data across formats).
    #[must_use]
    pub fn vaddr_in_string_section(&self, vaddr: u64, len: u64) -> bool {
        for &i in &self.string_sections {
            let sec = &self.sections[i];
            if vaddr >= sec.vaddr
                && vaddr
                    .checked_add(len)
                    .is_some_and(|e| e <= sec.vaddr + sec.size)
            {
                return true;
            }
        }
        false
    }

    /// Indices into `self.sections` of sections classified as hosting
    /// string bytes (`.rodata*`, `.rdata*`, `__cstring`, ...).
    #[must_use]
    pub fn string_section_indices(&self) -> &[usize] {
        &self.string_sections
    }

    /// All sections parsed from the object file (not all are guaranteed
    /// to contain parseable bytes — some are NOBITS or sparse).
    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Test-utility constructor: build a `Binary` from a set of
    /// precomputed sections and (optionally) symbols.
    ///
    /// Used by integration tests to construct minimal-but-representative
    /// blobs without going through goblin's parser. The internal indices
    /// are rebuilt from the provided sections before the function returns.
    /// `force_string_sections` lets a test bypass the name-based
    /// predicate and pin specific sections as string-hosting.
    ///
    /// ⚠️ Public-but-test-oriented. Production callers should use
    /// `Binary::parse`. The signature may change without notice.
    #[doc(hidden)]
    #[must_use]
    pub fn from_test_parts(
        format: BinaryFormat,
        is_64: bool,
        little_endian: bool,
        sections: Vec<Section>,
        symbols: Vec<Symbol>,
        force_string_sections: Vec<usize>,
    ) -> Self {
        let mut bin = Self {
            path: None,
            format,
            arch: "test".into(),
            is_64,
            little_endian,
            bytes: vec![],
            sections,
            symbols,
            sec_by_vaddr: Vec::new(),
            string_sections: Vec::new(),
        };
        bin.build_indices();
        bin.string_sections = force_string_sections;
        bin
    }
}

// ---------------------------------------------------------------------------
// parsers — each returns an owned `Binary` so the parsed view's borrows on
// the input buffer can be dropped before we hand the buffer back to the
// caller. This is the only end-of-fn ELF<'_>-in-scope-after-bytes-moved risk
// can be eliminated cleanly.
// ---------------------------------------------------------------------------

// We return `Result<Binary>` uniformly from all three loaders so that
// `Binary::parse`'s caller code stays symmetric. The inner loaders can't
// fail for ELF in v0.1, but we keep the signature stable for the day
// when they can (e.g., a malformed Mach-O archive detection).
#[allow(clippy::unnecessary_wraps)]
fn load_elf(path: Option<&str>, elf: &elf::Elf<'_>, bytes: Vec<u8>) -> Result<Binary> {
    let is_64 = elf.is_64;
    let little_endian = elf.little_endian;
    let arch = arch_name_elf(elf.header.e_machine);
    let cap = bytes.len();

    let mut sections: Vec<Section> = Vec::new();
    for sc in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sc.sh_name).unwrap_or("").to_string();
        let off = usize::try_from(sc.sh_offset)
            .expect("ELF: section file offset exceeds usize on this host");
        let sz = usize::try_from(sc.sh_size).expect("ELF: section size exceeds usize on this host");
        let data = if sz == 0 {
            Vec::new()
        } else if let Some(end) = off.checked_add(sz) {
            if off <= cap && end <= cap {
                bytes[off..end].to_vec()
            } else if off < cap {
                bytes[off..cap].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        sections.push(Section {
            name,
            vaddr: sc.sh_addr,
            size: sc.sh_size,
            data,
        });
    }

    let mut symbols: Vec<Symbol> = Vec::new();
    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sym.st_value == 0 {
            continue;
        }
        let Some(raw) = elf.strtab.get_at(sym.st_name) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        symbols.push(Symbol {
            vaddr: sym.st_value,
            name: raw.to_string(),
            size: sym.st_size,
        });
    }

    let mut bin = Binary {
        path: path.map(String::from),
        format: BinaryFormat::Elf,
        arch,
        is_64,
        little_endian,
        bytes,
        sections,
        symbols,
        sec_by_vaddr: Vec::new(),
        string_sections: Vec::new(),
    };
    bin.build_indices();
    Ok(bin)
}

#[allow(clippy::unnecessary_wraps)]
fn load_pe(path: Option<&str>, pe: &pe::PE<'_>, bytes: Vec<u8>) -> Result<Binary> {
    let is_64 = pe.is_64;
    let arch = arch_name_pe(pe.header.coff_header.machine);
    let cap = bytes.len();
    let base = pe.image_base as u64; // goblin types this as `usize`; `as` is lossless on supported targets

    let mut sections: Vec<Section> = Vec::new();
    for sc in &pe.sections {
        let name = sc.name().unwrap_or("").to_string();
        let off = usize::try_from(sc.pointer_to_raw_data)
            .expect("PE: section raw pointer exceeds usize on this host");
        let sz = usize::try_from(sc.size_of_raw_data)
            .expect("PE: section raw size exceeds usize on this host");
        let data = if sz == 0 {
            Vec::new()
        } else if let Some(end) = off.checked_add(sz) {
            if off <= cap && end <= cap {
                bytes[off..end].to_vec()
            } else if off < cap {
                bytes[off..cap].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let vaddr = base.wrapping_add(u64::from(sc.virtual_address));
        sections.push(Section {
            name,
            vaddr,
            size: u64::from(sc.virtual_size),
            data,
        });
    }

    let mut symbols: Vec<Symbol> = Vec::new();
    for exp in &pe.exports {
        let Some(raw) = exp.name else { continue };
        if raw.is_empty() {
            continue;
        }
        symbols.push(Symbol {
            vaddr: base.wrapping_add(exp.rva as u64),
            name: raw.to_string(),
            size: 0,
        });
    }

    let mut bin = Binary {
        path: path.map(String::from),
        format: BinaryFormat::Pe,
        arch,
        is_64,
        little_endian: true,
        bytes,
        sections,
        symbols,
        sec_by_vaddr: Vec::new(),
        string_sections: Vec::new(),
    };
    bin.build_indices();
    Ok(bin)
}

fn load_mach(path: Option<&str>, mach: &mach::Mach<'_>, bytes: Vec<u8>) -> Result<Binary> {
    let mach_bin = match mach {
        mach::Mach::Binary(b) => b,
        mach::Mach::Fat(_) => return Err(anyhow!("Mach-O fat archives are not supported")),
    };
    let is_64 = mach_bin.is_64;
    let mut sections: Vec<Section> = Vec::new();
    for seg_iter in mach_bin.segments.sections() {
        for entry in seg_iter {
            let (sc, data) = entry.context("mach-o section parse")?;
            let sectname = sc.name().unwrap_or("").to_string();
            let segname = sc.segname().unwrap_or("").to_string();
            let name = if segname.is_empty() {
                sectname
            } else {
                format!("{segname}.{sectname}")
            };
            sections.push(Section {
                name,
                vaddr: sc.addr,
                size: sc.size,
                data: data.to_vec(),
            });
        }
    }

    let mut bin = Binary {
        path: path.map(String::from),
        format: BinaryFormat::MachO,
        arch: String::from("macho"),
        is_64,
        little_endian: true,
        bytes,
        sections,
        symbols: Vec::new(),
        sec_by_vaddr: Vec::new(),
        string_sections: Vec::new(),
    };
    bin.build_indices();
    Ok(bin)
}

impl Binary {
    fn build_indices(&mut self) {
        for (i, sec) in self.sections.iter().enumerate() {
            let end = sec.vaddr.wrapping_add(sec.size);
            self.sec_by_vaddr.push((sec.vaddr, end, i));
        }
        self.sec_by_vaddr.sort_by_key(|(start, _end, _i)| *start);

        for (i, sec) in self.sections.iter().enumerate() {
            if is_string_section_name(&sec.name) {
                self.string_sections.push(i);
            }
        }
    }
}

fn read_le_ptr(bytes: &[u8], is_64: bool) -> u64 {
    if is_64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[..8]);
        u64::from_le_bytes(a)
    } else {
        let mut a = [0u8; 4];
        a.copy_from_slice(&bytes[..4]);
        u64::from(u32::from_le_bytes(a))
    }
}

fn read_be_ptr(bytes: &[u8], is_64: bool) -> u64 {
    if is_64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[..8]);
        u64::from_be_bytes(a)
    } else {
        let mut a = [0u8; 4];
        a.copy_from_slice(&bytes[..4]);
        u64::from(u32::from_be_bytes(a))
    }
}

fn is_string_section_name(name: &str) -> bool {
    if name == ".rodata" || name.starts_with(".rodata.") {
        return true;
    }
    if name == ".data.rel.ro" || name.starts_with(".data.rel.ro.") {
        return true;
    }
    if name == ".rdata" || name.starts_with(".rdata.") {
        return true;
    }
    if name == "__cstring" || name.starts_with("__cstring,") {
        return true;
    }
    if name == "__const" || name.starts_with("__const,") {
        return true;
    }
    false
}

fn arch_name_elf(machine: u16) -> String {
    use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_MIPS, EM_PPC64, EM_RISCV, EM_X86_64};
    match machine {
        EM_X86_64 => "x86_64".into(),
        EM_386 => "x86".into(),
        EM_AARCH64 => "aarch64".into(),
        EM_ARM => "arm".into(),
        EM_RISCV => "riscv".into(),
        EM_PPC64 => "ppc64".into(),
        EM_MIPS => "mips".into(),
        _ => format!("elf:{machine}"),
    }
}

fn arch_name_pe(machine: u16) -> String {
    use goblin::pe::header::{
        COFF_MACHINE_ARM, COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64,
    };
    match machine {
        COFF_MACHINE_X86_64 => "x86_64".into(),
        COFF_MACHINE_X86 => "x86".into(),
        COFF_MACHINE_ARM64 => "aarch64".into(),
        COFF_MACHINE_ARM => "arm".into(),
        _ => format!("pe:{machine}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_binary_empty() -> Binary {
        Binary {
            path: None,
            format: BinaryFormat::Elf,
            arch: "x86_64".into(),
            is_64: true,
            little_endian: true,
            bytes: vec![],
            sections: vec![Section {
                name: ".rodata".into(),
                vaddr: 0x2000,
                size: 0x1000,
                data: vec![0; 0x1000],
            }],
            symbols: vec![],
            sec_by_vaddr: vec![(0x2000, 0x3000, 0)],
            string_sections: vec![0],
        }
    }

    /// Direct unit tests for `arch_name_elf` covering every documented ELF
    /// architecture. cargo-mutants otherwise flags each individual match
    /// arm as uncaught because the only path we exercised was `x86_64`;
    /// these tests catch any future removal.
    #[test]
    fn arch_name_elf_x86_64() {
        assert_eq!(arch_name_elf(goblin::elf::header::EM_X86_64), "x86_64");
    }

    #[test]
    fn arch_name_elf_x86() {
        assert_eq!(arch_name_elf(goblin::elf::header::EM_386), "x86");
    }

    #[test]
    fn arch_name_elf_aarch64() {
        assert_eq!(arch_name_elf(goblin::elf::header::EM_AARCH64), "aarch64");
    }

    #[test]
    fn arch_name_elf_arm() {
        assert_eq!(arch_name_elf(goblin::elf::header::EM_ARM), "arm");
    }

    #[test]
    fn arch_name_elf_riscv() {
        assert_eq!(arch_name_elf(goblin::elf::header::EM_RISCV), "riscv");
    }

    #[test]
    fn arch_name_elf_ppc64() {
        assert_eq!(arch_name_elf(goblin::elf::header::EM_PPC64), "ppc64");
    }

    #[test]
    fn arch_name_elf_mips() {
        assert_eq!(arch_name_elf(goblin::elf::header::EM_MIPS), "mips");
    }

    #[test]
    fn arch_name_elf_unknown_emits_default() {
        assert_eq!(arch_name_elf(0xFFFF), "elf:65535");
    }

    #[test]
    fn arch_name_pe_x86_64() {
        assert_eq!(
            arch_name_pe(goblin::pe::header::COFF_MACHINE_X86_64),
            "x86_64"
        );
    }

    #[test]
    fn arch_name_pe_x86() {
        assert_eq!(arch_name_pe(goblin::pe::header::COFF_MACHINE_X86), "x86");
    }

    #[test]
    fn arch_name_pe_aarch64() {
        assert_eq!(
            arch_name_pe(goblin::pe::header::COFF_MACHINE_ARM64),
            "aarch64"
        );
    }

    #[test]
    fn arch_name_pe_arm() {
        assert_eq!(arch_name_pe(goblin::pe::header::COFF_MACHINE_ARM), "arm");
    }

    #[test]
    fn arch_name_pe_unknown_emits_default() {
        assert_eq!(arch_name_pe(0xBEEF), "pe:48879");
    }

    #[test]
    fn is_string_section_name_full_matrix_positive() {
        let positives = [
            ".rodata",
            ".rodata.1",
            ".rodata.foo.bar",
            ".data.rel.ro",
            ".data.rel.ro.local",
            ".rdata",
            ".rdata.0",
            "__cstring",
            "__cstring,FOO",
            "__const",
            "__const,FUNC",
        ];
        for n in positives {
            assert!(
                super::is_string_section_name(n),
                "{n} should be classified as string-hosting",
            );
        }
    }

    #[test]
    fn vaddr_lookup_in_range() {
        let b = fake_binary_empty();
        // nosemgrep: rustrip-no-unwrapping-trust-bytes (test code)
        let r = b.vaddr_to_offset(0x2000 + 5).unwrap();
        assert_eq!(r, (0, 5));
        assert!(b.vaddr_to_offset(0x3000).is_none());
        assert!(b.vaddr_to_offset(0x1FFF).is_none());
    }

    #[test]
    fn read_ptr_endianness_le() {
        let mut b = fake_binary_empty();
        // 0x1122_3344_5566_7788 little-endian
        b.sections[0].data[..8].copy_from_slice(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
        // nosemgrep: rustrip-no-unwrapping-trust-bytes (test code)
        assert_eq!(b.read_ptr(0x2000).unwrap(), 0x1122_3344_5566_7788);
    }

    #[test]
    fn string_section_recognized() {
        let b = fake_binary_empty();
        assert!(b.vaddr_in_string_section(0x2000, 1));
        assert!(b.vaddr_in_string_section(0x2800, 0x800));
        assert!(!b.vaddr_in_string_section(0x3000, 1));
    }
}
