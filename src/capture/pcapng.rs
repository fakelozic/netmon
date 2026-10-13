//! Converts bounded pcapng records into captured packets.
//! Format detection and timestamp scaling stay in `capture`.
//! Read `next_ng` for interface retention limits and metadata-only scan bounds.
//! An interface description declares the link header and timestamp resolution.

use super::{CaptureError, Input, RawPacket, timestamp};
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::blocks::{
    enhanced_packet::EnhancedPacketBlock, packet::PacketBlock, simple_packet::SimplePacketBlock,
};
use pcap_file::pcapng::{Block, PcapNgReader};
use std::time::Duration;

// pcapng defaults to microsecond ticks when IfTsResol is absent.
fn resolution(options: &[InterfaceDescriptionOption<'_>]) -> u8 {
    options
        .iter()
        .find_map(|o| match o {
            InterfaceDescriptionOption::IfTsResol(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(6)
}

/// Reads at most 65,536 intervening metadata blocks; limits fail once and end the reader.
pub(super) fn next_ng(
    r: &mut PcapNgReader<Input>,
    metadata: &mut usize,
) -> Option<Result<RawPacket, CaptureError>> {
    // 65,536 metadata blocks accommodate verbose captures but bound each call
    // even when an untrusted stream never produces a packet.
    for _ in 0..65_536 {
        match r.next_block().map(|b| b.map(|b| b.into_owned())) {
            None => return None,
            Some(Err(e)) => return Some(Err(e.into())),
            Some(Ok(Block::EnhancedPacket(p))) => return Some(enhanced(r, p)),
            Some(Ok(Block::SimplePacket(p))) => return Some(simple(r, p)),
            Some(Ok(Block::Packet(p))) => return Some(legacy(r, p)),
            Some(Ok(Block::SectionHeader(_))) => *metadata = 0,
            Some(Ok(Block::InterfaceDescription(interface))) => {
                // pcap-file keeps every interface in the current section. Cap both
                // count (4,096 interfaces) and owned options (4 MiB, a small fraction
                // of the packet budget) before requesting another block.
                *metadata = metadata.saturating_add(
                    interface
                        .options
                        .iter()
                        .map(option_bytes)
                        .fold(0usize, usize::saturating_add),
                );
                if r.interfaces().len() > 4096 || *metadata > 4 * 1024 * 1024 {
                    return Some(Err(CaptureError::Invalid(
                        "interface metadata limit exceeded".into(),
                    )));
                }
            }
            Some(Ok(_)) => {}
        }
    }
    Some(Err(CaptureError::Invalid(
        "too many blocks without a packet".into(),
    )))
}

fn option_bytes(option: &InterfaceDescriptionOption<'_>) -> usize {
    use InterfaceDescriptionOption::*;
    let payload = match option {
        Comment(v) | IfName(v) | IfDescription(v) | IfOs(v) | IfHardware(v) => v.len(),
        IfIpv4Addr(v) | IfIpv6Addr(v) | IfMacAddr(v) | IfFilter(v) => v.len(),
        CustomBinary(v) => v.value.len(),
        CustomUtf8(v) => v.value.len(),
        Unknown(v) => v.value.len(),
        _ => 0,
    };
    payload.saturating_add(std::mem::size_of_val(option))
}

fn enhanced(
    r: &PcapNgReader<Input>,
    p: EnhancedPacketBlock<'_>,
) -> Result<RawPacket, CaptureError> {
    let iface = r
        .packet_interface(&p)
        .ok_or_else(|| CaptureError::Invalid("unknown interface".into()))?;
    Ok(RawPacket {
        number: 0,
        ts: timestamp(p.timestamp.as_nanos(), resolution(&iface.options)),
        link: u32::from(iface.linktype).into(),
        iface: p.interface_id,
        orig_len: p.original_len,
        data: p.data.into_owned(),
    })
}

fn simple(r: &PcapNgReader<Input>, p: SimplePacketBlock<'_>) -> Result<RawPacket, CaptureError> {
    let iface = r
        .interfaces()
        .first()
        .ok_or_else(|| CaptureError::Invalid("missing interface".into()))?;
    // Zero snaplen means no capture limit. Remove block padding using the wire length.
    let captured = if iface.snaplen == 0 {
        p.original_len
    } else {
        p.original_len.min(iface.snaplen)
    } as usize;
    let data = p.data.get(..captured).ok_or(CaptureError::Truncated)?;
    Ok(RawPacket {
        number: 0,
        ts: Duration::ZERO,
        link: u32::from(iface.linktype).into(),
        iface: 0,
        orig_len: p.original_len,
        data: data.to_vec(),
    })
}

fn legacy(r: &PcapNgReader<Input>, p: PacketBlock<'_>) -> Result<RawPacket, CaptureError> {
    let iface = r
        .interfaces()
        .get(usize::from(p.interface_id))
        .ok_or_else(|| CaptureError::Invalid("unknown interface".into()))?;
    // pcap-file reads a u64 here, but this block stores high and low u32 words.
    let ticks = if r.section().endianness == pcap_file::Endianness::Little {
        p.timestamp.rotate_left(32)
    } else {
        p.timestamp
    };
    Ok(RawPacket {
        number: 0,
        ts: timestamp(u128::from(ticks), resolution(&iface.options)),
        link: u32::from(iface.linktype).into(),
        iface: u32::from(p.interface_id),
        orig_len: p.original_len,
        data: p.data.into_owned(),
    })
}
