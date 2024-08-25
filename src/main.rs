#![no_main]
#![no_std]
#![feature(strict_provenance, let_chains)]

use core::{ffi::c_void, ptr::NonNull};
use log::{info, error};
use qemu_fw_cfg::FwCfg;
use uefi::{boot::{self, EventType, MemoryType, ScopedProtocol, SearchType}, prelude::*, proto::pci::PciIo, Event};
use zeroize::Zeroize;

static mut PCI_IO_KEY: Option<SearchType<'static>> = None;

fn opregion_setup(pci_io: &mut ScopedProtocol<PciIo>) -> Status {
	let mut fw_cfg = unsafe { FwCfg::new_for_x86().unwrap() };
	let opregion = fw_cfg.find_file("etc/igd-opregion");

	if opregion.is_none() {
		error!("OpRegion not passed through!");
		return Status::INVALID_PARAMETER;
	}

	let opregion = opregion.unwrap();

	if opregion.size() == 0 {
		error!("OpRegion has zero size!");
		return Status::INVALID_PARAMETER;
	}

	let pages = opregion.size().div_ceil(0x1000);
	let buf = boot::allocate_pages(boot::AllocateType::MaxAddress(0xFFFFFFFF), MemoryType::ACPI_NON_VOLATILE, pages).unwrap();
	let buf_slice = unsafe {
		core::slice::from_raw_parts_mut(buf.as_ptr(), pages * 0x1000)
	};
	buf_slice.zeroize();

	fw_cfg.read_file_to_buffer(&opregion, buf_slice);

	let addr: usize = buf.addr().into();

	pci_io.pci_write(4, 0xFC, 1, &addr as *const usize as *mut c_void).unwrap();

	info!("OpRegion @ {:#x} ({} bytes)", addr, opregion.size());

	return Status::SUCCESS;
}

fn stolen_memory_setup(pci_io: &mut ScopedProtocol<PciIo>) -> Status {
	let mut fw_cfg = unsafe { FwCfg::new_for_x86().unwrap() };

	let bdsm = fw_cfg.find_file("etc/igd-bdsm-size");
	if bdsm.is_none() {
		error!("BDSM data not passed through!");
		return Status::INVALID_PARAMETER;
	}

	let bdsm = bdsm.unwrap();

	let mut bdsm_buf: [u8; 8] = [0; 8];
	fw_cfg.read_file_to_buffer(&bdsm, &mut bdsm_buf);
	let bdsm_size = usize::from_le_bytes(bdsm_buf);

	if bdsm_size == 0 {
		return Status::INVALID_PARAMETER;
	}

	if !(bdsm_size % 0x1000 == 0) {
		error!("BDSM size {} is not page-aligned!", bdsm_size);
		return Status::INVALID_PARAMETER;
	}

	let pages = bdsm_size / 0x1000;
	// we overallocate 1 MiB - 1 page to ensure our stolen memory range has proper alignment
	let stolen_memory = boot::allocate_pages(boot::AllocateType::MaxAddress(0xFFFFFFFF),
		MemoryType::ACPI_NON_VOLATILE, pages + 255).unwrap();

	unsafe {
		core::slice::from_raw_parts_mut(stolen_memory.as_ptr(), pages * 0x1000).zeroize();
	}

	// the allocation for stolen memory needs to be aligned to 1 MiB
	let alignment_needed = stolen_memory.align_offset(1 * 1024 * 1024);
	let aligned_mem = unsafe { stolen_memory.add(alignment_needed) };
	let addr: usize = aligned_mem.addr().into();

	pci_io.pci_write(4, 0x5C, 1, &addr as *const usize as *mut c_void).unwrap();

	info!("StolenMemory @ {:#x} ({} MiB)", addr, (pages * 0x1000) / 1024 / 1024);

	Status::SUCCESS
}

unsafe extern "efiapi" fn notify(_e: Event, _ctx: Option<NonNull<c_void>>) {
	assert!(PCI_IO_KEY.is_some());

	while let buf = boot::locate_handle_buffer(PCI_IO_KEY.unwrap()) && buf.is_ok() {
		match buf {
			Ok(d) => {
				assert!(d.len() > 0);

				let mut pci_io = boot::open_protocol_exclusive::<PciIo>(d[0]).unwrap();

				let mut vendor: [u8; 2] = [0; 2];
				pci_io.pci_read(2, 0, 1, &mut vendor).expect("PCI configuration space read failed");

				if u16::from_le_bytes(vendor) != 0x8086 {
					continue;
				}

				let mut classes: [u8; 3] = [0; 3];
				pci_io.pci_read(1, 9, 3, &mut classes).expect("PCI configuration space read failed");

				if classes[2] != 3 || classes[1] != 0 || classes[0] != 0 {
					continue;
				}

				let _ = opregion_setup(&mut pci_io);

				let (seg, bus, dev, func) = pci_io.get_location().unwrap();

				if seg != 0 || bus != 0 || dev != 2 || func != 0 {
					continue;
				}

				let _ = stolen_memory_setup(&mut pci_io);
			}
			Err(_) => error!("Failed to obtain PCI_IO handle buffer"),
		}
	}
}

#[entry]
fn main(_image_handle: Handle, system_table: SystemTable<Boot>) -> Status {
	uefi::helpers::init().unwrap();

	unsafe {
		let status = uefi::boot::create_event(EventType::NOTIFY_SIGNAL, uefi::boot::Tpl::CALLBACK, Some(notify), None);

		if status.is_err() {
			error!("create_event failed with status {:?}!", status.status());
			return status.status();
		}

		let event = status.unwrap();

		let status = uefi::boot::register_protocol_notify(
			&uefi_raw::protocol::pci_io::PciIoProtocol::GUID, &event
		);

		if status.is_err() {
			error!("register_protocol_notify failed with status {:?}!", status.status());
			let _ = uefi::boot::close_event(event);
			return status.status();
		}

		PCI_IO_KEY = Some(status.unwrap());

		// HACK: kick the event to handle existing PCI_IO protocol instances
		let status = uefi::boot::signal_event(&event);

		if status.is_err() {
			error!("signal_event failed with status {:?}!", status.status());
			let _ = uefi::boot::close_event(event);
			return status.status();
		}
	}

	Status::SUCCESS
}
