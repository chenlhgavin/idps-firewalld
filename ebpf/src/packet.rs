use aya_ebpf::programs::TcContext;

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = 14;
const IPV4_MIN_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[derive(Clone, Copy, Debug, Default)]
pub struct PacketMetaV4 {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub len: u32,
    pub ifindex: u32,
}

pub fn parse_ipv4_packet(ctx: &TcContext) -> Option<PacketMetaV4> {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let required = ETH_HDR_LEN + IPV4_MIN_HDR_LEN + UDP_HDR_LEN;
    ctx.pull_data(required as u32).ok()?;

    let eth_proto = u16::from_be(ctx.load::<u16>(12).ok()?);
    if eth_proto != ETH_P_IP as u16 {
        return None;
    }

    let version_ihl = ctx.load::<u8>(ETH_HDR_LEN).ok()?;
    if (version_ihl >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(version_ihl & 0x0f) * 4;
    if ihl < IPV4_MIN_HDR_LEN {
        return None;
    }
    ctx.pull_data((ETH_HDR_LEN + ihl + TCP_HDR_LEN) as u32).ok()?;

    let proto = ctx.load::<u8>(ETH_HDR_LEN + 9).ok()?;
    let src_ip = u32::from_be(ctx.load::<u32>(ETH_HDR_LEN + 12).ok()?);
    let dst_ip = u32::from_be(ctx.load::<u32>(ETH_HDR_LEN + 16).ok()?);

    let l4_offset = ETH_HDR_LEN + ihl;
    let (src_port, dst_port) = match proto {
        IPPROTO_TCP => (
            u16::from_be(ctx.load::<u16>(l4_offset).ok()?),
            u16::from_be(ctx.load::<u16>(l4_offset + 2).ok()?),
        ),
        IPPROTO_UDP => (
            u16::from_be(ctx.load::<u16>(l4_offset).ok()?),
            u16::from_be(ctx.load::<u16>(l4_offset + 2).ok()?),
        ),
        _ => (0, 0),
    };

    Some(PacketMetaV4 {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        len: ctx.len(),
        ifindex,
    })
}
