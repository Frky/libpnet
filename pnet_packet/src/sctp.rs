//! A SCTP packet abstraction.

extern crate crc;

use self::crc::crc32;
use std::net::{Ipv4Addr, Ipv6Addr};
use Packet;
use PrimitiveValues;

use pnet_macros::packet;
use pnet_macros_support::types::*;

/// Represents a generic SCTP Packet.
#[packet]
pub struct Sctp {
    pub source: u16be,
    pub destination: u16be,
    pub tag: u32be,
    pub checksum: u32be,
    #[payload]
    pub payload: Vec<u8>,
}

impl SctpPacket<'_> {
    pub fn compute_checksum(&self) -> u32 {
        crc32::checksum_castagnoli(self.packet())
    }

    pub fn get_chunks(&self) -> Vec<SctpChunk> {
        let mut i = 0;
        let mut chunks = Vec::<SctpChunk>::new();
        while i < self.payload().len() {
            let chunk = SctpChunkGenericPacket::new(&self.payload()[i..]).expect("Error creating a SctpChunkGenericPacket");
            i += chunk.get_length() as usize;
            let chunk = match chunk.get_type_() {
                SctpChunkTypes::INIT => SctpChunk::Init(
                    SctpChunkInitPacket::owned(chunk.packet().clone().to_vec()).expect("Error creating a SctpChunkInitPacket"),
                ),
                SctpChunkTypes::INIT_ACK => SctpChunk::InitAck(
                    SctpChunkInitAckPacket::owned(chunk.packet().clone().to_vec()).expect("Error creating a SctpChunkInitAckPacket"),
                ),
                _ => SctpChunk::Generic(
                    SctpChunkGenericPacket::owned(chunk.packet().clone().to_vec()).expect("SctpChunkGenericPacket"),
                ),
            };
            chunks.push(chunk);
        }
        chunks
    }
}

/// Definition of SCTP chunks
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SctpChunkType(pub u8);

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod SctpChunkTypes {
    use super::SctpChunkType;
    pub const DATA: SctpChunkType = SctpChunkType(0);
    pub const INIT: SctpChunkType = SctpChunkType(1);
    pub const INIT_ACK: SctpChunkType = SctpChunkType(2);
    pub const SACK: SctpChunkType = SctpChunkType(3);
    pub const HEARTBEAT: SctpChunkType = SctpChunkType(4);
    pub const HEARTBEAT_ACK: SctpChunkType = SctpChunkType(5);
    pub const ABORT: SctpChunkType = SctpChunkType(6);
    pub const SHUTDOWN: SctpChunkType = SctpChunkType(7);
    pub const SHUTDOWN_ACK: SctpChunkType = SctpChunkType(8);
    pub const ERROR: SctpChunkType = SctpChunkType(9);
    pub const COOKIE_ECHO: SctpChunkType = SctpChunkType(10);
    pub const COOKIE_ACK: SctpChunkType = SctpChunkType(11);
}

impl SctpChunkType {
    pub fn new(value: u8) -> SctpChunkType {
        SctpChunkType(value)
    }
}

impl PrimitiveValues for SctpChunkType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// Implementation of the different chunk types
#[packet]
pub struct SctpChunkGeneric {
    #[construct_with(u8)]
    pub type_: SctpChunkType,
    pub flags: u8,
    pub length: u16be,
    #[length_fn = "sctp_chunk_length"]
    #[payload]
    pub payload: Vec<u8>,
}

#[packet]
pub struct SctpChunkInit {
    #[construct_with(u8)]
    pub type_: SctpChunkType,
    pub flags: u8,
    pub length: u16be,
    pub init_tag: u32be,
    pub a_rwnd: u32be,
    pub n_out_streams: u16be,
    pub n_in_streams: u16be,
    pub init_tsn: u32be,
    #[length_fn = "sctp_chunk_init_length"]
    #[payload]
    pub payload: Vec<u8>,
}

#[packet]
pub struct SctpChunkInitAck {
    #[construct_with(u8)]
    pub type_: SctpChunkType,
    pub flags: u8,
    pub length: u16be,
    pub init_tag: u32be,
    pub a_rwnd: u32be,
    pub n_out_streams: u16be,
    pub n_in_streams: u16be,
    pub init_tsn: u32be,
    #[length_fn = "sctp_chunk_init_ack_length"]
    #[payload]
    pub payload: Vec<u8>,
}

pub enum SctpChunk<'a> {
    Generic(SctpChunkGenericPacket<'a>),
    Init(SctpChunkInitPacket<'a>),
    InitAck(SctpChunkInitAckPacket<'a>),
}

impl SctpChunk<'_> {
    /* generic method to get payload from any type of chunk */
    pub fn get_payload(&self) -> &[u8] {
        match self {
            SctpChunk::Generic(p) => p.payload(),
            SctpChunk::Init(p) => p.payload(),
            SctpChunk::InitAck(p) => p.payload(),
        }
    }

    pub fn get_type_(&self) -> SctpChunkType {
        match self {
            SctpChunk::Generic(p) => p.get_type_(),
            SctpChunk::Init(p) => p.get_type_(),
            SctpChunk::InitAck(p) => p.get_type_(),
        }
    }
}

/// Definition of the various chunk option types
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SctpChunkOptionType(pub u16be);

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod SctpChunkOptionTypes {
    use super::SctpChunkOptionType;
    pub const IPV4_ADDR: SctpChunkOptionType = SctpChunkOptionType(5);
    pub const IPV6_ADDR: SctpChunkOptionType = SctpChunkOptionType(6);
    pub const STATE_COOKIE: SctpChunkOptionType = SctpChunkOptionType(7);
    pub const UNRECOGNIZED_PARAMETER: SctpChunkOptionType = SctpChunkOptionType(8);
    pub const COOKIE_PRESERVATIVE: SctpChunkOptionType = SctpChunkOptionType(9);
    pub const HOSTNAME_ADDR: SctpChunkOptionType = SctpChunkOptionType(11);
    pub const SUPPORTED_ADDR_TYPES: SctpChunkOptionType = SctpChunkOptionType(12);
}

impl SctpChunkOptionType {
    pub fn new(value: u16be) -> SctpChunkOptionType {
        SctpChunkOptionType(value)
    }
}

impl PrimitiveValues for SctpChunkOptionType {
    type T = (u16be,);
    fn to_primitive_values(&self) -> (u16be,) {
        (self.0,)
    }
}

/// Implementation of chunk options
#[packet]
pub struct SctpChunkOptionGeneric {
    #[construct_with(u16be)]
    pub type_: SctpChunkOptionType,
    pub length: u16be,
    #[length_fn = "sctp_chunk_option_length"]
    #[payload]
    pub payload: Vec<u8>,
}

#[packet]
pub struct SctpChunkOptionIpv4Addr {
    #[construct_with(u16be)]
    pub type_: SctpChunkOptionType,
    pub length: u16be,
    #[construct_with(u8, u8, u8, u8)]
    pub addr: Ipv4Addr,
    #[length = "0"]
    #[payload]
    pub payload: Vec<u8>,
}

#[packet]
pub struct SctpChunkOptionIpv6Addr {
    #[construct_with(u16be)]
    pub type_: SctpChunkOptionType,
    pub length: u16be,
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    pub addr: Ipv6Addr,
    #[length = "0"]
    #[payload]
    pub payload: Vec<u8>,
}

pub enum SctpChunkOption<'a> {
    Generic(SctpChunkOptionGenericPacket<'a>),
    Ipv4Addr(SctpChunkOptionIpv4AddrPacket<'a>),
    Ipv6Addr(SctpChunkOptionIpv6AddrPacket<'a>),
    StateCookie(SctpChunkOptionGenericPacket<'a>),
    UnrecognizedParameter(SctpChunkOptionGenericPacket<'a>),
    HostnameAddr(SctpChunkOptionGenericPacket<'a>),
}

fn sctp_chunk_option_length(option: &SctpChunkOptionGenericPacket) -> usize {
    (option.get_length() - 4) as usize
}

impl SctpChunkInitPacket<'_> {
    pub fn get_options(&self) -> Vec<SctpChunkOption> {
        let mut i = 0;
        let mut options = Vec::<SctpChunkOption>::new();
        while i < self.payload().len() {
            let option = SctpChunkOptionGenericPacket::new(&self.payload()[i..]).expect("Error creating a SctpChunkOptionGenericPacket");
            i += option.get_length() as usize;
            options.push(match option.get_type_() {
                /* XXX TODO */
                /*
                 * - cookie preservative
                 * - supported address types
                 *
                 */
                SctpChunkOptionTypes::IPV4_ADDR => SctpChunkOption::Ipv4Addr(
                    SctpChunkOptionIpv4AddrPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionIpv4AddrPacket"),
                ),
                SctpChunkOptionTypes::IPV6_ADDR => SctpChunkOption::Ipv6Addr(
                    SctpChunkOptionIpv6AddrPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionIpv6AddrPacket"),
                ),
                SctpChunkOptionTypes::HOSTNAME_ADDR => SctpChunkOption::HostnameAddr(
                    SctpChunkOptionGenericPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionGenericPacket"),
                ),
                _ => SctpChunkOption::Generic(
                    SctpChunkOptionGenericPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionGenericPacket"),
                ),
            });
            /* RFC 4960
             * The total length of a parameter (including Type, Parameter Length,
             * and Value fields) MUST be a multiple of 4 bytes.  If the length of
             * the parameter is not a multiple of 4 bytes, the sender pads the
             * parameter at the end (i.e., after the Parameter Value field) with
             * all zero bytes.  The length of the padding is not included in the
             * Parameter Length field.  A sender MUST NOT pad with more than 3
             * bytes.  The receiver MUST ignore the padding bytes.
             */
            while i % 4 != 0 {
                i += 1;
            }
        }
        options
    }
}

impl SctpChunkInitAckPacket<'_> {
    pub fn get_options(&self) -> Vec<SctpChunkOption> {
        let mut i = 0;
        let mut options = Vec::<SctpChunkOption>::new();
        while i < self.payload().len() {
            let option = SctpChunkOptionGenericPacket::new(&self.payload()[i..]).expect("Error creating a SctpChunkOptionGenericPacket");
            i += option.get_length() as usize;
            options.push(match option.get_type_() {
                /* XXX TODO */
                /*
                 * - ECN capable
                 *
                 */
                SctpChunkOptionTypes::IPV4_ADDR => SctpChunkOption::Ipv4Addr(
                    SctpChunkOptionIpv4AddrPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionIpv4AddrPacket"),
                ),
                SctpChunkOptionTypes::IPV6_ADDR => SctpChunkOption::Ipv6Addr(
                    SctpChunkOptionIpv6AddrPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionIpv6AddrPacket"),
                ),
                SctpChunkOptionTypes::STATE_COOKIE => SctpChunkOption::StateCookie(
                    SctpChunkOptionGenericPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionGenericPacket"),
                ),
                SctpChunkOptionTypes::UNRECOGNIZED_PARAMETER => {
                    SctpChunkOption::UnrecognizedParameter(
                        SctpChunkOptionGenericPacket::owned(option.packet().clone().to_vec())
                            .expect("Error creating a SctpChunkOptionGenericPacket"),
                    )
                }
                SctpChunkOptionTypes::HOSTNAME_ADDR => SctpChunkOption::HostnameAddr(
                    SctpChunkOptionGenericPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionGenericPacket"),
                ),
                _ => SctpChunkOption::Generic(
                    SctpChunkOptionGenericPacket::owned(option.packet().clone().to_vec()).expect("Error creating a SctpChunkOptionGenericPacket"),
                ),
            });
            /* RFC 4960
             * The total length of a parameter (including Type, Parameter Length,
             * and Value fields) MUST be a multiple of 4 bytes.  If the length of
             * the parameter is not a multiple of 4 bytes, the sender pads the
             * parameter at the end (i.e., after the Parameter Value field) with
             * all zero bytes.  The length of the padding is not included in the
             * Parameter Length field.  A sender MUST NOT pad with more than 3
             * bytes.  The receiver MUST ignore the padding bytes.
             */
            while i % 4 != 0 {
                i += 1;
            }
        }
        options
    }
}

fn sctp_chunk_length(chunk: &SctpChunkGenericPacket) -> usize {
    (chunk.get_length() - 4) as usize
}

fn sctp_chunk_init_length(chunk: &SctpChunkInitPacket) -> usize {
    (chunk.get_length() - 20) as usize
}

fn sctp_chunk_init_ack_length(chunk: &SctpChunkInitAckPacket) -> usize {
    (chunk.get_length() - 20) as usize
}

/// TESTS
#[test]
fn sctp_checksum_zeros() {
    let mut packet = [0u8; 2 + 2 + 4 + 4];
    let mut sctp = MutableSctpPacket::new(&mut packet).expect("Error creating a MutableSctpPacket");
    let cs = sctp.to_immutable().compute_checksum();
    sctp.set_checksum(cs);
    assert!(sctp.get_checksum() == 0x2b60b55d);
}

#[test]
fn sctp_checksum_non_zero() {
    let mut packet = b"\xad\xff6\xb0\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x146\xaa\x80\xfe\x00\x00\x80\x00\x00\n\x08\x00F\x1a\xdf=".clone();
    let mut sctp = MutableSctpPacket::new(&mut packet).expect("Error creating a MutableSctpPacket");
    let cs = sctp.to_immutable().compute_checksum();
    sctp.set_checksum(cs);
    assert!(sctp.get_checksum() == 0xc690ae74);
}

#[test]
fn sctp_chunk_init() {
    let packet = [
        1,
        0,
        0,
        20 + 4 + 7,
        1,
        2,
        3,
        4,
        0x10,
        0x11,
        0x12,
        0x13,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xca,
        0xfe,
        0xca,
        0xfe,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let init_ack = SctpChunkInitPacket::new(&packet).expect("Error creating a SctpChunkInitPacket");
    assert!(init_ack.get_type_() == SctpChunkTypes::INIT);
    assert!(init_ack.get_flags() == 0);
    assert!(init_ack.get_length() == 31);
    assert!(init_ack.get_init_tag() == 0x01020304);
    assert!(init_ack.get_a_rwnd() == 0x10111213);
    assert!(init_ack.get_n_out_streams() == 0xaabb);
    assert!(init_ack.get_n_in_streams() == 0xccdd);
    assert!(init_ack.get_init_tsn() == 0xcafecafe);
}

#[test]
fn sctp_chunk_init_ack() {
    /* Packet crafted with Scapy used for test
     * >>> p = SCTP(sport=12345, dport=54321, tag=0xccddeeff)/SCTPChunkInitAck(flags=0xab, init_tag=0x04030201, a_rwnd=65000, n_out_streams=17536, n_in_streams=63571
     * ...:, init_tsn=13, params=[SCTPChunkParamIPv4Addr() , SCTPChunkParamStateCookie(cookie="c00ki3")])
     * >>> p.show2()
     * ###[ SCTP ]###
     *   sport= 12345
     *   dport= 54321
     *   tag= 0xccddeeff
     *   chksum= 0x4b77e61e
     * ###[ SCTPChunkInitAck ]###
     *      type= init-ack
     *      flags= 0xab
     *      len= 40
     *      init_tag= 0x4030201
     *      a_rwnd= 65000
     *      n_out_streams= 17536
     *      n_in_streams= 63571
     *      init_tsn= 0xd
     *      \params\
     *       |###[ SCTPChunkParamIPv4Addr ]###
     *       |  type= IPv4
     *       |  len= 8
     *       |  addr= 127.0.0.1
     *       |###[ SCTPChunkParamStateCookie ]###
     *       |  type= state-cookie
     *       |  len= 10
     *       |  cookie= 'c00ki3'
     *
     * >>> raw(p)                                                                                                                                                    ,
     * b'09\xd41\xcc\xdd\xee\xffKw\xe6\x1e\x02\xab\x00(\x04\x03\x02\x01\x00\x00\xfd\xe8D\x80\xf8S\x00\x00\x00\r\x00\x05\x00\x08\x7f\x00\x00\x01\x00\x07\x00\nc00ki3\x'00\x00'
     */
    let packet = b"09\xd41\xcc\xdd\xee\xffKw\xe6\x1e\x02\xab\x00(\x04\x03\x02\x01\x00\x00\xfd\xe8D\x80\xf8S\x00\x00\x00\r\x00\x05\x00\x08\x7f\x00\x00\x01\x00\x07\x00\nc00ki3\x00\x00".clone();
    let pkt = SctpPacket::new(&packet).expect("Error creating a SctpPacket");
    /* checks on SCTP header */
    assert!(pkt.get_source() == 12345);
    assert!(pkt.get_destination() == 54321);
    assert!(pkt.get_tag() == 0xccddeeff);
    assert!(pkt.get_checksum() == 0x4b77e61e);
    let chunks = pkt.get_chunks();
    assert!(chunks.len() == 1);
    let chunk = &chunks[0];
    /* check on INIT ACK chunk */
    assert!(chunk.get_type_() == SctpChunkTypes::INIT_ACK);
    let chunk = if let SctpChunk::InitAck(p) = chunk {
        p
    } else {
        panic!("Not a INIT ACK packet");
    };
    assert!(chunk.get_flags() == 0xab);
    assert!(chunk.get_length() == 40);
    assert!(chunk.get_init_tag() == 0x04030201);
    assert!(chunk.get_a_rwnd() == 65000);
    assert!(chunk.get_n_out_streams() == 17536);
    assert!(chunk.get_n_in_streams() == 63571);
    assert!(chunk.get_init_tsn() == 13);
    let options = chunk.get_options();
    assert!(options.len() == 2);
    /* check IPv4 Option */
    let option_ipv4 = if let SctpChunkOption::Ipv4Addr(o) = &options[0] {
        o
    } else {
        panic!("Not an \"IPv4 address\" option");
    };
    assert!(option_ipv4.get_length() == 2 + 2 + 4);
    assert!(option_ipv4.get_addr() == Ipv4Addr::new(127, 0, 0, 1));
    /* check State Cookie option */
    let option_state_cookie = if let SctpChunkOption::StateCookie(o) = &options[1] {
        o
    } else {
        panic!("Not a \"State Cookie\" option");
    };
    assert!(option_state_cookie.get_length() == 2 + 2 + 6);
    assert!(option_state_cookie.payload() == b"c00ki3".to_vec());
}
