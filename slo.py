"""
SLO: Slow Lossless Operation
A relatively simple reliable data transport protocol loosely based on TCP, QUIC, BBR and TCP Vegas

Algorithms used:
    Path MTU Discovery: Normal ICMP based PMTUD performed by the underlying socket
        and DPLPMTUD (Datagram Packetization Layer Path MTU Discovery) which is a loss-based
        MTU probing algorithm, the implemenation in this is based on quic-go loss-tolerance DPLPMTUD
    Flow control: Keep in-flight data below the receiver window size and nothing else
    Congestion control: Fast start + QRPI (Quadratic Ratio Packets Interval)
        Which will start the connection at the highest send rate possible and slow down
        the packets interval base on the ratio between RTT and min RTT
    Retransmission: Timeout based retransmission + fast retransmission based on selective acknowledgment and reordering threshold
    Constant values are usually based on existing standards but can be modified where appropriate

Terms:
    - Datagram: A chunk of data sent over the UDP socket
    - Packet: A chunk of data sent over the tranceiver
    - Data : A chunk of data sent over the file transceiver
    - Packet number: A sequential number for each packet sent
    - Retransmission number: A sequential number for each retransmission sent, starting at 0 for first packet

A connection is a session of data transfer, one connection can transfer only a single chunk of data (or a single file)

Packets number is per-connection, starting at a random number and increment by one every packet
Retransmitted packets have the same packet number and incremented retransmission number

Packets are variable length (due to path MTU discovery being asynchronous)
but retransmitted packets are the same size as their lost original to simplify
data reassembly and selective acknowledgement

ACK packets:
    ACK packet and transmission number is always the same as the original packet to aid in rtt calculation
    SACK is used to ack packets that are not the current one

Start Packet Layout:
    1 byte: Packet type (0)
    6 bytes: Packet number
    2 byte: Transmission number
    4 bytes: Data size
    4 bytes: Sender MDS (Maximum Datagram Size)
    2 bytes: Transmission size (of this packet)
    n bytes: Padding

Start-ACK Packet Layout:
    1 byte: Packet type (1)
    6 bytes: ACK packet number
    2 byte: ACK transmission number
    4 bytes: Receiver MDS (Maximum Datagram Size)
    4 bytes: Receiver window size

Data Packet Layout:
    1 byte: Packet type (2)
    6 bytes: Packet number
    2 byte: Transmission number
    n bytes: Payload

ACK Packet Layout:
    1 byte: Packet type (3)
    6 bytes: ACK packet number
    2 byte: ACK transmission number
    6 bytes: CACK number (Cumulative ack, all packets before and including the CACK number have been received)
    n bytes: SACK struct

FIN Packet Layout:
    1 byte: Packet type (4)

FIN ACK Packet Layout:
    1 byte: Packet type (5)

PMTUD-Probe Packet Layout:
    1 byte: Packet type (6)
    4 bytes: Probe ID
    2 bytes: Transmission size (of this packet)
    n bytes: Padding

PMTUD-ACK Packet Layout:
    1 byte: Packet type (7)
    4 bytes: Probe ID

SACK struct:
    n bytes of m ranges: {
        1 bytes: Gap (The gap (in packets) from the last acked packet in this ack)
        1 bytes: Length (The length (in packets) from the end of the gap)
    }

SACK Example:
    Packet received: 11 12 15 16 17 19 25 26 27 28
    Current Packet: 31
    ACK number: 31
    CACK number: 12
    SACK: [
        {
            gap: 2 (13 14)
            length: 3 (15 16 17)
        },
        {
            gap: 1 (18)
            length: 1 (19)
        },
        {
            gap: 5 (20 21 22 23 24)
            length: 4 (25 26 27 28)
        }
    ]

If gap or lenght exceed 255, SACK will end at the range before that
"""

import dataclasses
import errno
import hashlib
import hmac
import logging
import random
import select
import socket
import sys
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

import compat

# How big the datagram can be relative to the MTU
DATAGRAM_SIZE_OFFSET = 20 + 8  # IP header + UDP header

# Try to set the receive/transmit buffer size to 256 KiB
# This should succeed on most systems but smaller buffers is supported
SOCKET_TRY_RCVBUF_SIZE = 256 * 1024
SOCKET_TRY_SNDBUF_SIZE = 256 * 1024

# 4 MB window size used for flow control
# This is the maximum amount of un-acked in-flight data
WINDOW_SIZE = 4 * 1024 * 1024

# Shared key for HMAC signing and verification
# Any packets that fails verification are assumed to not be for this application
HMAC_KEY = b"\x8fe\xec\xf4\xa9\xfb\xca\\\xd0\xe4\x08@\xf2u\xda{\x8a\xd9\x1e\xc0s\x0cL\xac\r\xa7\x9d\xe7\x9dc?\xae"
HMAC_ALGORITHM = "sha256"

# Winsock constants that are not available from the socket module
# Option names
WS_IP_MTU_DISCOVER = 71
WS_IP_MTU = 73
# Option values
WS_IP_PMTUDISC_NOT_SET = 0
WS_IP_PMTUDISC_DO = 1
WS_IP_PMTUDISC_DONT = 2
WS_IP_PMTUDISC_PROBE = 3
WS_IP_PMTUDISC_MAX = 4

# Socket constants that are not avaialble from the socket module
# Option names
SO_IP_MTU_DISCOVER = 10
SO_IP_MTU = 14
# Option values
SO_IP_PMTUDISC_DONT = 0
SO_IP_PMTUDISC_WANT = 1
SO_IP_PMTUDISC_DO = 2
SO_IP_PMTUDISC_PROBE = 3

# Clock granularity, set to a conservative 1 ms.
CLOCK_GRANULARITY = 0.001

# Minimum MTU for DPLPMTUD binary search algorithm and others
# If path MTU is lower than this then IP fragmentation will be enabled
MIN_MTU = 576

# Maximum MTU for capping OS returned MTU values
# as loopback interfaces can have MTU much higher than the normal limit
# This is to prevent those high values from breaking other algorithms
# which rely on realistic MTU value
MAX_MTU = 65535

# How many time to try to initiate connection with each preset MTU
# MTU value may be increased later via DPLPMTUD
INIT_MTU_RETRY = 5

# How many time to try to use the minimum MTU to initiate connection without IP fragmentation
# After this many retries IP fragmentation will be enable and no further PMTUD will be performed
INIT_NOFRAG_RETRY = 10

# Maximum amount of lost probes before declaring a MTU as unsupported by path
# Base on experimentations: 3 is a good value for low loss network (5-10%)
# and 5 is a good value for high loss network (10-20%)
# The default is set to a conservative 5
MAX_LOST_DPLPMTUD_PROBES = 5

# The guaranteed bandwidth of the link, congestion controller will not drop the rate below this
# This exist to prevent a congestion controller bug from halting the entire connection
GUARANTEED_BANDWIDTH = 125_000  # 125 kB/s = 1 Mbps

# The max bandwidth expected to encounter, used for fast start algorithm
MAX_BANDWIDTH = 12_500_000  # 12.5 MB/s = 100 Mbps

# How many packets received/lost event the packet loss tracker will keep track of
LOSS_TRACKER_WINDOW = 400

# The flat RTT congestion threshold, if smoothed RTT is lower than this then it's assume that there's no congestion,
# even if the ratio says otherwise. This is due to the fact that QRPI does not work well and is way too sensitive at lower RTT values
# Mostly used to speed up loopback and high speed links
QRPI_FLAT_CONGESTION_THRESHOLD = 0.001

# The multiplier for RTT variance before being added to smoothed RTT to calculate adjusted RTT
QRPI_VARIANCE_MULTIPLIER = 0.25

# The minimum ratio between RTT and min RTT to be interpreted as a congestion event
QRPI_MIN_CONGESTED_RATIO = 1.25

# The exponent value to determine scaling behavior of the congestion controller
QRPI_CONGESTION_EXPONENT = 2

# If unacknowledged packet is behind the latest acknowledged packet by this amount of packets
# it is considered lost immediately without having to wait for time out similary to TCP fast retransmit
PACKET_REORDERING_THRESHOLD = 3

# How many packets to try to delete when cleanup is called
# Cleanup will looks at first N packets that is still tracker and delete them if they're no longer needed
# If packets that are being deleted are in order, more packets may be removed
CLEANUP_MIN_CHECK_COUNT = 16

# If cleanup have looked at more than the minimum check count and the gaps between packets
# that should be removed is more than this value, cleanup will terminate
CLEANUP_MAX_GAP = 4

# The amount of time to wait in the FIN-WAIT period
FIN_WAIT_DURATION = 3  # seconds


logger = logging.getLogger(__name__)

Addr = Tuple[str, int]


class PacketTypes:
    START = bytes([0])
    START_ACK = bytes([1])
    DATA = bytes([2])
    ACK = bytes([3])
    FIN = bytes([4])
    FIN_ACK = bytes([5])
    PMTUD_PROBE = bytes([6])
    PMTUD_ACK = bytes([7])


class MessageTooLong(IOError):
    pass


class SocketFull(IOError):
    pass


class SocketNotConnected(ValueError):
    pass


class SocketNotBinded(ValueError):
    pass


class ConnectionEnding(ConnectionError):
    pass


@dataclasses.dataclass
class PacketData:
    start: int  # The index of the start byte contained in this packet
    size: int  # The amount of payload data contained in this packet
    acknowledged: bool  # Whether this packet have been acknowledged by the receiver
    confirm_lost: bool  # Whether this packet have been declared lost by reason other than timeout
    timestamps: List[float]  # The time when each of the transmission was sent
    # A set containing all transmission numbers that have received their corresponding ack, used to prevent duplicated packets from influencing RTT calculatino
    acked_transmission_numbers: Set[int]


class Signer:
    def __init__(self, key: bytes, algorithm: str) -> None:
        self.__key: bytes = key
        self.__algorithm: str = algorithm
        self.__digest_size: int = hashlib.new(algorithm).digest_size

    def sign(self, data: bytes) -> bytes:
        return hmac.digest(self.__key, data, self.__algorithm)

    def verify(self, data: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(signature, self.sign(data))

    @property
    def digest_size(self) -> int:
        return self.__digest_size


# Class for parsing selective ACKs
class Sack:
    def __init__(self, start: int, data: bytes) -> None:
        self.__values: Set[int] = set()
        current: int = start
        for i in range(0, len(data), 2):
            gap: int = data[i]
            length: int = data[i + 1]
            self.__values.update(range(current + gap, current + gap + length))
            current += gap + length
        self.__max_val: int = current - 1 if data else -1

    def __contains__(self, val: int) -> bool:
        return val in self.__values

    @property
    def values(self) -> Set[int]:
        return self.__values

    @property
    def end(self) -> int:
        return self.__max_val


class Transceiver:
    def __init__(
        self,
        signing_key: bytes,
        signing_algorithm: str,
        rcvbuf_size: int,
        sndbuf_size: int,
        do_pmtud: bool,
    ):
        self.__signer: Signer = Signer(signing_key, signing_algorithm)
        self.__checksum_size: int = self.__signer.digest_size
        self.__socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__connected_addr: Optional[Addr] = None

        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf_size)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf_size)

        # Enable or disable path MTU discovery (OS specific, not tested on MacOS)
        if do_pmtud and sys.platform.startswith("win"):
            self.__socket.setsockopt(socket.IPPROTO_IP, WS_IP_MTU_DISCOVER, WS_IP_PMTUDISC_DO)
        elif do_pmtud:
            self.__socket.setsockopt(socket.IPPROTO_IP, SO_IP_MTU_DISCOVER, SO_IP_PMTUDISC_DO)
        if not do_pmtud and sys.platform.startswith("win"):
            self.__socket.setsockopt(socket.IPPROTO_IP, WS_IP_MTU_DISCOVER, WS_IP_PMTUDISC_DONT)
        elif not do_pmtud:
            self.__socket.setsockopt(socket.IPPROTO_IP, SO_IP_MTU_DISCOVER, SO_IP_PMTUDISC_DONT)

        self.__socket.settimeout(None)  # Set socket to blocking mode

        logger.debug("Socket created")
        logger.debug(f"Requested receive buffer size: {rcvbuf_size}")
        logger.debug(f"Requested send buffer size: {sndbuf_size}")

        self.__rcvbuf_size: int = self.__socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        self.__sndbuf_size: int = self.__socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)

        logger.debug(f"Actual receive buffer size: {self.__rcvbuf_size}")
        logger.debug(f"Actual send buffer size: {self.__sndbuf_size}")

    @property
    def checksum_size(self) -> int:
        return self.__checksum_size

    @property
    def rcvbuf_size(self) -> int:
        return self.__rcvbuf_size

    @property
    def sndbuf_size(self) -> int:
        return self.__sndbuf_size

    def __is_readable(self) -> bool:
        readables, _, _ = select.select([self.__socket], [], [], 0)
        return bool(readables)

    def __is_writeable(self) -> bool:
        _, writables, _ = select.select([], [self.__socket], [], 0)
        return bool(writables)

    def set_pmtud(self, enabled: bool) -> None:
        if enabled and sys.platform.startswith("win"):
            self.__socket.setsockopt(socket.IPPROTO_IP, WS_IP_MTU_DISCOVER, WS_IP_PMTUDISC_DO)
        elif enabled:
            self.__socket.setsockopt(socket.IPPROTO_IP, SO_IP_MTU_DISCOVER, SO_IP_PMTUDISC_DO)
        if not enabled and sys.platform.startswith("win"):
            self.__socket.setsockopt(socket.IPPROTO_IP, WS_IP_MTU_DISCOVER, WS_IP_PMTUDISC_DONT)
        elif not enabled:
            self.__socket.setsockopt(socket.IPPROTO_IP, SO_IP_MTU_DISCOVER, SO_IP_PMTUDISC_DONT)

    def bind(self, addr: Addr) -> None:
        self.__socket.bind(addr)

    def connect(self, addr: Addr) -> None:
        self.__connected_addr = addr
        self.__socket.connect(addr)

    def close(self) -> None:
        self.__socket.close()

    def recvfrom(
        self, timeout: Optional[float], accept_addr: Optional[Addr] = None
    ) -> Tuple[bytes, Addr]:
        start: float = time.perf_counter()

        while True:
            while (
                timeout is None or timeout > 0 and time.perf_counter() - start < timeout
            ) and not self.__is_readable():
                pass

            if not self.__is_readable():
                raise TimeoutError("No data available")

            try:
                datagram_data, addr = self.__socket.recvfrom(self.__rcvbuf_size)
                addr: Addr = (addr[0], addr[1])
            except ConnectionError:
                logger.debug("OS terminated connection, retrying")
                continue
            except OSError as err:
                if (
                    hasattr(err, "winerror")
                    and err.winerror == 10040
                    or not hasattr(err, "winerror")
                    and err.errno == errno.EMSGSIZE
                ):
                    logger.debug("Message too long raised on recvfrom, ignoring and retrying")
                    continue
                logger.warning("An unexpected OS error occured, retrying", exc_info=True)
                continue

            signature, data = (
                datagram_data[0 : self.__checksum_size],
                datagram_data[self.__checksum_size :],
            )

            if accept_addr is not None and addr != accept_addr:
                logger.debug(f"Received data from unexpected address {addr}, discarding")
                continue

            if not self.__signer.verify(data, signature):
                logger.debug("Received data with invalid signature, discarding")
                continue

            return data, addr

    def recv(self, timeout: Optional[float]) -> bytes:
        if self.__connected_addr is None:
            raise SocketNotConnected("Socket is not connected to an address")

        start: float = time.perf_counter()

        while True:
            while (
                timeout is None or timeout > 0 and time.perf_counter() - start < timeout
            ) and not self.__is_readable():
                pass

            if not self.__is_readable():
                raise TimeoutError("No data available")

            try:
                datagram_data = self.__socket.recv(self.__rcvbuf_size)
            except ConnectionError:
                logger.debug("OS terminated connection, retrying")
                continue
            except OSError as err:
                if (
                    hasattr(err, "winerror")
                    and err.winerror == 10040
                    or not hasattr(err, "winerror")
                    and err.errno == errno.EMSGSIZE
                ):
                    logger.debug("Message too long raised on recv, ignoring and retrying")
                    continue
                logger.warning("An unexpected OS error occured, retrying", exc_info=True)
                continue

            signature, data = (
                datagram_data[0 : self.__checksum_size],
                datagram_data[self.__checksum_size :],
            )

            if not self.__signer.verify(data, signature):
                logger.debug("Received data with invalid signature, discarding")
                continue

            return data

    @property
    def mtu(self) -> int:
        if self.__connected_addr is None:
            raise SocketNotConnected("Socket is not connected to an address")

        if sys.platform.startswith("win"):
            return min(self.__socket.getsockopt(socket.IPPROTO_IP, WS_IP_MTU), MAX_MTU)
        else:
            return min(self.__socket.getsockopt(socket.IPPROTO_IP, SO_IP_MTU), MAX_MTU)

    def send(self, data: bytes, wait: bool = True) -> int:
        if self.__connected_addr is None:
            raise SocketNotConnected("Socket is not connected to an address")

        datagram = self.__signer.sign(data) + data

        if not wait and not self.__is_writeable():
            logger.debug("Socket is full, data not sent")
            raise SocketFull("Socket is full")

        try:
            return self.__socket.send(datagram)
        except ConnectionError:
            logger.debug("OS terminated connection, ignoring")
            return -1
        except OSError as err:
            if (
                hasattr(err, "winerror")
                and err.winerror == 10040
                or not hasattr(err, "winerror")
                and err.errno == errno.EMSGSIZE
            ):
                logger.debug(
                    f"Transmission size exceeded OS determined path MTU, datagram size: {len(datagram)}"
                )
                raise MessageTooLong("Transmission size exceeded OS determined path MTU") from err
            logger.warning("An unexpected OS error occured, ignoring", exc_info=True)
            return -1

    def sendto(self, data: bytes, addr: Addr, wait: bool = True) -> int:
        datagram = self.__signer.sign(data) + data

        if not wait and not self.__is_writeable():
            logger.debug("Socket is full, data not sent")
            raise SocketFull("Socket is full")

        try:
            return self.__socket.sendto(datagram, addr)
        except ConnectionError:
            logger.debug("OS terminated connection, ignoring")
            return -1
        except OSError as err:
            if (
                hasattr(err, "winerror")
                and err.winerror == 10040
                or not hasattr(err, "winerror")
                and err.errno == errno.EMSGSIZE
            ):
                logger.debug(
                    f"Transmission size exceeded OS determined path MTU, datagram size: {len(datagram)}"
                )
                raise MessageTooLong("Transmission size exceeded OS determined path MTU") from err
            logger.warning("An unexpected OS error occured, ignoring", exc_info=True)
            return -1


class ReliableReceiver:
    def __init__(
        self,
        listen_addr: Addr,
        signing_key: bytes = HMAC_KEY,
        signing_algorithm: str = HMAC_ALGORITHM,
        rcvbuf_size: int = SOCKET_TRY_RCVBUF_SIZE,
        sndbuf_size: int = SOCKET_TRY_SNDBUF_SIZE,
        window_size: int = WINDOW_SIZE,
        init_mtu: int = MIN_MTU,  # Use static initial MTU value for simplicity, this will be increased by DPLPMTUD if possible
    ) -> None:
        self.__transceiver: Transceiver = Transceiver(
            signing_key, signing_algorithm, rcvbuf_size, sndbuf_size, False
        )
        self.__transceiver.bind(listen_addr)

        self.__window_size: int = window_size
        self.__mtu: int = init_mtu
        self.__checksum_size: int = self.__transceiver.checksum_size
        self.__sndbuf_size: int = self.__transceiver.sndbuf_size
        self.__rcvbuf_size: int = self.__transceiver.rcvbuf_size
        self.__max_datagram_size: int = self.__rcvbuf_size // 2

    def __get_max_sack_in_ack_packet(self) -> int:
        return (
            min(
                self.__remote_mds - self.__checksum_size - 1 - 6 - 2 - 6,
                self.__sndbuf_size - self.__checksum_size - 1 - 6 - 2 - 6,
                self.__mtu - DATAGRAM_SIZE_OFFSET - self.__checksum_size - 1 - 6 - 2 - 6,
            )
            // 2
        )

    def __get_cack_sack(self) -> bytes:
        max_ranges: int = self.__get_max_sack_in_ack_packet()
        self.__cumulative_ack = max(self.__cumulative_ack, 0)
        while (
            self.__cumulative_ack < len(self.__packets)
            and self.__packets[self.__cumulative_ack][0] == self.__cumulative_ack
        ):
            self.__cumulative_ack += 1
        self.__cumulative_ack -= 1
        i: int = self.__cumulative_ack + 1
        ack: int = self.__cumulative_ack + 1
        ranges: List[bytes] = []
        while i < len(self.__packets) and len(ranges) < max_ranges:
            gap: int = 0
            length: int = 0
            while i < len(self.__packets) and self.__packets[i][0] != ack:
                ack += 1
                gap += 1
            while i < len(self.__packets) and self.__packets[i][0] == ack:
                i += 1
                ack += 1
                length += 1
            if gap > 255 or length > 255:
                break
            ranges.append(gap.to_bytes(1, "big") + length.to_bytes(1, "big"))

        return (self.__first_packet_number + self.__cumulative_ack).to_bytes(6, "big") + b"".join(
            ranges
        )

    def __wait_for_connection(self) -> None:
        logger.info("Waiting for connection...")
        while True:
            req, req_addr = self.__transceiver.recvfrom(None)
            req_type, req_data = req[0:1], req[1:]
            if req_type == PacketTypes.PMTUD_PROBE:
                logger.debug(
                    "Received path MTU discovery probe during connection initialization, updating MTU and acknowledging"
                )
                probe_id, transmission_size = req_data[0:4], req_data[4:6]
                self.__transceiver.sendto(PacketTypes.PMTUD_ACK + probe_id, req_addr)
                self.__mtu = max(self.__mtu, int.from_bytes(transmission_size, "big"))
                continue
            if req_type != PacketTypes.START:
                logger.debug(
                    "Received non-START packet during connection initialization, discarding"
                )
                continue
            packet_number, transmission_number, data_size, max_datagram_size, transmission_size = (
                req_data[0:6],
                req_data[6:8],
                req_data[8:12],
                req_data[12:16],
                req_data[16:18],
            )
            self.__transceiver.connect(req_addr)
            self.__first_packet_number: int = int.from_bytes(packet_number, "big") + 1
            self.__data_size: int = int.from_bytes(data_size, "big")
            self.__remote_mds: int = int.from_bytes(max_datagram_size, "big")
            self.__mtu = max(self.__mtu, int.from_bytes(transmission_size, "big"))
            self.__transceiver.send(
                PacketTypes.START_ACK
                + packet_number
                + transmission_number
                + self.__max_datagram_size.to_bytes(4, "big")
                + self.__window_size.to_bytes(4, "big"),
            )
            logger.info(
                f"Connection established with {req_addr}, MTU: {self.__mtu}, Remote MDS: {self.__remote_mds}, Data size: {self.__data_size} bytes, First data packet number: {self.__first_packet_number}"
            )
            break

    def __end_connection(self) -> None:
        def recv_fin(timeout: float) -> bool:
            start: float = time.perf_counter()
            while time.perf_counter() - start < timeout:
                try:
                    resp = self.__transceiver.recv(0)
                    resp_type = resp[0:1]
                    if resp_type == PacketTypes.FIN:
                        return True
                except TimeoutError:
                    continue
            return False

        while True:
            self.__transceiver.send(PacketTypes.FIN)
            if recv_fin(0.1):
                self.__transceiver.send(PacketTypes.FIN_ACK)
                logger.debug("Received FIN packet, entering FIN-WAIT period")
                break
        while True:
            try:
                resp = self.__transceiver.recv(FIN_WAIT_DURATION)
                resp_type = resp[0:1]
                if resp_type == PacketTypes.FIN:
                    self.__transceiver.send(PacketTypes.FIN_ACK)
                    logger.debug("Received FIN packet, acknowledging")
                    continue
                if resp_type == PacketTypes.FIN_ACK:
                    logger.debug("Received FIN-ACK, ending FIN-WAIT early")
                    break
            except TimeoutError:
                logger.debug("FIN-WAIT period ended")
                break
        logger.info("Connection terminated")

    def recv(self) -> bytes:
        self.__wait_for_connection()
        self.__cumulative_ack: int = 0
        self.__packets: List[Tuple[int, bytes]] = []
        self.__received: int = 0

        last_info_log_message: float = -1.0
        start_time: float = time.perf_counter()

        while self.__received < self.__data_size:
            if time.perf_counter() - last_info_log_message > 1.0:
                logger.info(
                    f"Current progress: {self.__received}/{self.__data_size} bytes ({self.__received / self.__data_size * 100:.3f}%)"
                )
                last_info_log_message = time.perf_counter()
            try:
                req = self.__transceiver.recv(0.1)
                req_type, req_data = req[0:1], req[1:]
            except TimeoutError:
                continue
            if req_type == PacketTypes.START:
                logger.debug("Received duplicate START packet, acknowledging")
                packet_number, transmission_number = req_data[0:6], req_data[6:8]
                self.__transceiver.send(
                    PacketTypes.START_ACK
                    + packet_number
                    + transmission_number
                    + self.__max_datagram_size.to_bytes(4, "big")
                    + self.__window_size.to_bytes(4, "big"),
                )
                continue
            if req_type == PacketTypes.PMTUD_PROBE:
                logger.debug("Received path MTU discovery probe, updating MTU and acknowledging")
                probe_id, transmission_size = req_data[0:4], req_data[4:6]
                self.__transceiver.send(PacketTypes.PMTUD_ACK + probe_id)
                self.__mtu = max(self.__mtu, int.from_bytes(transmission_size, "big"))
                continue
            if req_type == PacketTypes.DATA:
                original_packet_number, transmission_number, payload = (
                    req_data[0:6],
                    req_data[6:8],
                    req_data[8:],
                )
                packet_number = int.from_bytes(original_packet_number, "big")
                transmission_number = int.from_bytes(transmission_number, "big")
                packet_number = packet_number - self.__first_packet_number
                packet_index: int = compat.bisect_left(
                    self.__packets, packet_number, key=lambda x: x[0]
                )
                if (
                    packet_index >= len(self.__packets)
                    or self.__packets[packet_index][0] != packet_number
                ):
                    self.__packets.insert(packet_index, (packet_number, payload))
                    self.__received += len(payload)
                self.__transceiver.send(
                    PacketTypes.ACK
                    + original_packet_number
                    + transmission_number.to_bytes(2, "big")
                    + self.__get_cack_sack()
                )
                logger.debug(f"Received data at {packet_number}, size: {len(payload)}")
                continue
            logger.debug("Received unexpected packet type, discarding")
        logger.info(
            f"Current progress: {self.__received}/{self.__data_size} bytes ({self.__received / self.__data_size * 100:.3f}%)"
        )
        logger.info("Received all data successfully, ending connection")
        self.__end_connection()
        self.__transceiver.close()
        logger.info(f"Transmission took {time.perf_counter() - start_time:.3f} s.")
        return b"".join((payload for _, payload in self.__packets))


class ReliableTransmitter:
    def __init__(
        self,
        remote_addr: Addr,
        signing_key: bytes = HMAC_KEY,
        signing_algorithm: str = HMAC_ALGORITHM,
        rcvbuf_size: int = SOCKET_TRY_RCVBUF_SIZE,
        sndbuf_size: int = SOCKET_TRY_SNDBUF_SIZE,
        init_mtus: Optional[List[int]] = None,
        min_mtu: int = MIN_MTU,
        max_lost_dplpmtud_probes: int = MAX_LOST_DPLPMTUD_PROBES,
        guaranteed_bandwidth: int = GUARANTEED_BANDWIDTH,
        max_bandwidth: int = MAX_BANDWIDTH,
    ) -> None:
        if init_mtus is None:
            self.__init_mtus: List[int] = [9000, 1500, 1420, 1280, 1024, 576]
        else:
            self.__init_mtus: List[int] = init_mtus

        self.__transceiver: Transceiver = Transceiver(
            signing_key, signing_algorithm, rcvbuf_size, sndbuf_size, True
        )
        self.__transceiver.connect(remote_addr)

        self.__remote_addr: Addr = remote_addr
        self.__max_lost_probes: int = max_lost_dplpmtud_probes
        self.__guaranteed_bandwidth: int = guaranteed_bandwidth
        self.__max_bandwidth: int = max_bandwidth
        self.__checksum_size: int = self.__transceiver.checksum_size
        self.__sndbuf_size: int = self.__transceiver.sndbuf_size
        self.__rcvbuf_size: int = self.__transceiver.rcvbuf_size
        self.__max_datagram_size: int = self.__rcvbuf_size // 2
        self.__packet_number: int = random.randint(2**8 - 1, 2**24 - 1)
        self.__disable_dplpmtud: bool = False
        self.__min_mtu: int = min_mtu
        self.__low_mtu: int = self.__min_mtu
        self.__high_mtu: int = self.__transceiver.mtu
        self.__mtu: int = self.__low_mtu
        if self.__high_mtu < self.__min_mtu:
            logger.warning(
                f"OS determined path MTU is lower that what the application is designed support, this will lead to degraded performance. Required MTU: {self.__min_mtu} Socket MTU: {self.__high_mtu}"
            )
            self.__disable_dplpmtud = True
            self.__transceiver.set_pmtud(False)
            self.__mtu = self.__min_mtu
            self.__init_mtus = [self.__mtu]
        else:
            self.__init_mtus = [mtu for mtu in self.__init_mtus if mtu <= self.__high_mtu]
            if self.__high_mtu not in self.__init_mtus:
                self.__init_mtus.append(self.__high_mtu)
            if self.__low_mtu not in self.__init_mtus:
                self.__init_mtus.append(self.__low_mtu)
            self.__init_mtus.sort(reverse=True)
        logger.info(f"Interface MTU is {self.__high_mtu}")
        logger.debug(f"Connection initialization will try to use MTU values: {self.__init_mtus}")

    def __init_rtt_stats(self, initial_rtt: float) -> None:
        self.__latest_rtt: float = initial_rtt
        self.__min_rtt: float = initial_rtt
        self.__smoothed_rtt: float = initial_rtt
        self.__rtt_variance: float = initial_rtt / 2

    def __update_rtt_stats(self, rtt: float) -> None:
        self.__latest_rtt = rtt
        self.__min_rtt = min(self.__min_rtt, rtt)
        self.__smoothed_rtt = 0.875 * self.__smoothed_rtt + 0.125 * rtt
        self.__rtt_variance = 0.75 * self.__rtt_variance + 0.25 * abs(self.__smoothed_rtt - rtt)
        logger.debug(
            f"Current RTT stats: Latest: {self.__latest_rtt:.6f}, Min: {self.__min_rtt:.6f}, Smoothed: {self.__smoothed_rtt:.6f}, Variance: {self.__rtt_variance:.6f}"
        )

    def __init_loss_stats(self) -> None:
        self.__packets_lost_info: deque[bool] = deque()
        self.__packet_lost: int = 0
        self.__packet_loss_rate: float = 0.0

    def __update_loss_stats(self, lost: bool) -> None:
        self.__packet_lost += lost
        self.__packets_lost_info.append(lost)
        if len(self.__packets_lost_info) > LOSS_TRACKER_WINDOW:
            self.__packet_lost -= self.__packets_lost_info.popleft()
        self.__packet_loss_rate = self.__packet_lost / len(self.__packets_lost_info)
        logger.debug(f"Current packet loss rate: {self.__packet_loss_rate * 100:.2f}%")
        if self.__packet_lost == len(self.__packets_lost_info):
            logger.warning(
                "Packet loss rate have reached 100%, assuming path MTU reduction is the cause, enabling IP fragmentation"
            )
            self.__disable_dplpmtud = True
            self.__transceiver.set_pmtud(False)
            self.__mtu = self.__min_mtu

    def __get_timeout(self) -> float:
        return 1.125 * max(self.__smoothed_rtt, self.__latest_rtt) + max(
            4 * self.__rtt_variance, CLOCK_GRANULARITY
        )

    def __get_dplpmtud_interval(self) -> float:
        return 1.25 * max(self.__smoothed_rtt, self.__latest_rtt) + max(
            4 * self.__rtt_variance, CLOCK_GRANULARITY
        )

    def __get_packets_tracker_timeout(self) -> float:
        return 2.0 * max(self.__smoothed_rtt, self.__latest_rtt) + max(
            4 * self.__rtt_variance, CLOCK_GRANULARITY
        )

    def __get_pacing_interval(self) -> float:
        min_congested_rtt: float = self.__min_rtt * QRPI_MIN_CONGESTED_RATIO
        adjusted_smooth_rtt: float = (
            self.__smoothed_rtt + self.__rtt_variance * QRPI_VARIANCE_MULTIPLIER
        )

        if (
            adjusted_smooth_rtt <= min_congested_rtt
            or adjusted_smooth_rtt <= QRPI_FLAT_CONGESTION_THRESHOLD
        ):
            # The link is not congested, pace at maximum bandwidth
            return self.__mtu / self.__max_bandwidth

        congestion_ratio: float = adjusted_smooth_rtt / min_congested_rtt
        logger.debug(
            f"Congestion detected, congestion ratio: {congestion_ratio:.6f} Slowing down send rate"
        )
        return min(
            congestion_ratio**QRPI_CONGESTION_EXPONENT * self.__mtu / self.__max_bandwidth,
            self.__mtu / self.__guaranteed_bandwidth,
        )

    def __wait_for_pace(self) -> None:
        self.__receive_all()
        self.__log_info()
        stop: float = self.__last_send_at + self.__get_pacing_interval()
        while stop - time.perf_counter() > 0.0001:
            self.__receive_all()
        while stop > time.perf_counter():
            pass
        self.__last_send_at = time.perf_counter()
        return

    def __get_packet_number(self) -> int:
        self.__packet_number += 1
        return self.__packet_number

    def __get_max_data_in_packet(self) -> int:
        return min(
            self.__remote_mds - self.__checksum_size - 1 - 6 - 2,
            self.__sndbuf_size - self.__checksum_size - 1 - 6 - 2,
            self.__mtu - DATAGRAM_SIZE_OFFSET - self.__checksum_size - 1 - 6 - 2,
        )

    def __log_info(self, ignore_timer: bool = False) -> None:
        if not ignore_timer and time.perf_counter() - self.__last_info_log_message < 1.0:
            return
        logger.info(
            f"Current RTT stats: Latest: {self.__latest_rtt:.6f}, Min: {self.__min_rtt:.6f}, Smoothed: {self.__smoothed_rtt:.6f}, Variance: {self.__rtt_variance:.6f}"
        )
        logger.info(f"Current packet loss rate: {self.__packet_loss_rate * 100:.2f}%")
        logger.info(
            f"Current congestion control rate: {8 * self.__mtu / self.__get_pacing_interval() / 1_000_000:,.3f} Mb/s"
        )
        logger.info(
            f"Current progress: {self.__received}/{self.__data_size} bytes ({self.__received / self.__data_size * 100:.3f}%)"
        )
        self.__last_info_log_message = time.perf_counter()

    def __init_connection(self, data_size: int):
        # transmission_number: (send_timestamp, transmission_size)
        timestamps: Dict[int, Tuple[float, int]] = {}
        logger.info(f"Initiating connection to {self.__remote_addr}")
        try_mtu_index: int = 0
        current_mtu_try_count: int = 0
        packet_number: int = self.__get_packet_number()
        self.__first_packet_number: int = packet_number + 1
        transmission_number: int = 0
        self.__init_loss_stats()
        while True:
            if (
                current_mtu_try_count >= INIT_MTU_RETRY
                and try_mtu_index < len(self.__init_mtus) - 1
            ):
                try_mtu_index += 1
                current_mtu_try_count = 0
            try_mtu: int = self.__init_mtus[try_mtu_index]
            if current_mtu_try_count >= INIT_NOFRAG_RETRY and not self.__disable_dplpmtud:
                logger.info(
                    f"Failed to start connection with transmission size {try_mtu} after {INIT_NOFRAG_RETRY} tries, giving up and enabling IP fragmentation"
                )
                self.__disable_dplpmtud = True
                self.__transceiver.set_pmtud(False)
                self.__init_mtus = [self.__mtu]
                try_mtu_index = 0
                current_mtu_try_count = 0
                continue
            padding_size: int = (
                try_mtu - DATAGRAM_SIZE_OFFSET - self.__checksum_size - 1 - 6 - 2 - 4 - 4 - 2
            )
            padding: bytes = compat.randbytes(padding_size)
            try:
                self.__transceiver.send(
                    PacketTypes.START
                    + packet_number.to_bytes(6, "big")
                    + transmission_number.to_bytes(2, "big")
                    + data_size.to_bytes(4, "big")
                    + self.__max_datagram_size.to_bytes(4, "big")
                    + try_mtu.to_bytes(2, "big")
                    + padding
                )
            except MessageTooLong:
                logger.debug(
                    f"Got message too long error when sending start message of size:{self.__init_mtus[try_mtu_index]}, updating MTU"
                )
                new_mtu: int = self.__transceiver.mtu
                self.__high_mtu = min(self.__high_mtu, new_mtu)
                self.__low_mtu = min(self.__low_mtu, new_mtu)
                if self.__high_mtu < self.__min_mtu:
                    logger.warning(
                        f"OS determined path MTU is lower that what the application is designed support, this will lead to degraded performance. Required MTU: {self.__min_mtu} Socket MTU: {self.__high_mtu}"
                    )
                    self.__disable_dplpmtud = True
                    self.__transceiver.set_pmtud(False)
                    self.__mtu = self.__min_mtu
                    self.__init_mtus = [self.__mtu]
                    try_mtu_index = 0
                    current_mtu_try_count = 0
                    continue
                self.__init_mtus = [mtu for mtu in self.__init_mtus if mtu <= self.__high_mtu]
                if self.__high_mtu not in self.__init_mtus:
                    self.__init_mtus.append(self.__high_mtu)
                self.__init_mtus.sort(reverse=True)
                logger.info(f"OS updated path MTU, new MTU: {new_mtu}")
                try_mtu_index = 0
                current_mtu_try_count = 0
                continue
            timestamps[transmission_number] = time.perf_counter(), try_mtu
            transmission_number += 1
            current_mtu_try_count += 1
            logger.debug(
                f"Sent START packet with transmission size: {self.__init_mtus[try_mtu_index]}, try: #{current_mtu_try_count}"
            )
            try:
                resp = self.__transceiver.recv(0.1)
                resp_type, resp_data = resp[0:1], resp[1:]
                if resp_type != PacketTypes.START_ACK:
                    logger.debug(
                        "Receive non-START_ACK packet during connection initialization, discarding"
                    )
                    continue
                ack_packet_number, ack_transmission_number, max_datagram_size, window_size = (
                    resp_data[0:6],
                    resp_data[6:8],
                    resp_data[8:12],
                    resp_data[12:16],
                )
                ack_packet_number = int.from_bytes(ack_packet_number, "big")
                ack_transmission_number = int.from_bytes(ack_transmission_number, "big")
                if ack_packet_number != packet_number:
                    logger.debug("Received Start-ACK packet with unknown packet number, discarding")
                    continue
                if ack_transmission_number not in timestamps:
                    logger.debug(
                        "Received Start-ACK packet with unknown transmission number, discarding"
                    )
                    continue
                rtt: float = time.perf_counter() - timestamps[ack_transmission_number][0]
                mtu: int = timestamps[ack_transmission_number][1]
                self.__init_rtt_stats(rtt)
                self.__low_mtu = max(self.__low_mtu, mtu)
                self.__mtu: int = mtu
                self.__remote_mds: int = int.from_bytes(max_datagram_size, "big")
                self.__remote_window_size: int = int.from_bytes(window_size, "big")
                self.__last_send_at: float = time.perf_counter()
                logger.info(
                    f"Connection established, RTT: {rtt:.6f}, MTU: {mtu}, Remote MDS: {self.__remote_mds}, Remote window size: {self.__remote_window_size}, First data packet number: {self.__first_packet_number}"
                )
                break
            except TimeoutError:
                logger.debug("Timed out waiting for START_ACK, retrying")
                continue

    def __handle_data_ack(self, ack_data: bytes) -> None:
        ack_packet_number, ack_transmission_number, ack_cumulative_number, ack_sack_data = (
            ack_data[0:6],
            ack_data[6:8],
            ack_data[8:14],
            ack_data[14:],
        )
        ack_packet_number = int.from_bytes(ack_packet_number, "big")
        ack_transmission_number = int.from_bytes(ack_transmission_number, "big")
        ack_cumulative_number = int.from_bytes(ack_cumulative_number, "big")
        try:
            packet_data: PacketData = self.__packets[ack_packet_number]
            if ack_transmission_number not in packet_data.acked_transmission_numbers:
                rtt: float = time.perf_counter() - packet_data.timestamps[ack_transmission_number]
                self.__update_rtt_stats(rtt)
                packet_data.acked_transmission_numbers.add(ack_transmission_number)
            else:
                logger.debug(
                    f"Received duplicate ACK for packet #{ack_packet_number - self.__first_packet_number}, discarding"
                )
                return
        except LookupError:
            logger.debug("Received invalid ACK or ACK is referencing expired packet, discarding")
            return
        sack: Sack = Sack(ack_cumulative_number + 1, ack_sack_data)
        logger.debug(f"Received ACK for packet #{ack_packet_number - self.__first_packet_number}")
        logger.debug(
            f"CACK: {ack_cumulative_number - self.__first_packet_number}, SACK: {[val - self.__first_packet_number for val in sorted(sack.values)]}"
        )
        last_acknowledged: int = max(ack_cumulative_number, sack.end)
        for packet_number, packet_data in self.__packets.items():
            if packet_number > last_acknowledged:
                break
            if not packet_data.acknowledged and (
                packet_number == ack_packet_number
                or packet_number <= ack_cumulative_number
                or packet_number in sack
            ):
                packet_data.acknowledged = True
                packet_data.confirm_lost = False
                self.__update_loss_stats(False)
                self.__inflight -= packet_data.size
                self.__received += packet_data.size
                continue
            if (
                not packet_data.acknowledged
                and not packet_data.confirm_lost
                and packet_number <= last_acknowledged - PACKET_REORDERING_THRESHOLD
            ):
                packet_data.confirm_lost = True

    def __handle_dplpmtud_ack(self, ack_data: bytes) -> None:
        if ack_data[0:4] == self.__last_dplpmtud_probe_id:
            self.__last_dplpmtud_probe_lost = False

    def __receive_all(self) -> None:
        while True:
            try:
                ack = self.__transceiver.recv(0)
                ack_type, ack_data = ack[0:1], ack[1:]
                if ack_type == PacketTypes.ACK:
                    self.__handle_data_ack(ack_data)
                elif ack_type == PacketTypes.PMTUD_ACK:
                    self.__handle_dplpmtud_ack(ack_data)
                elif ack_type == PacketTypes.FIN:
                    logger.info("Server requested connection termination, ending connection")
                    raise ConnectionEnding("Server terminating connection")
            except TimeoutError:
                break

    def __dplpmtud(self) -> None:
        self.__wait_for_pace()
        if abs(self.__high_mtu - self.__low_mtu) <= 4:
            logger.info(f"DPLPMTUD completed, discovered MTU: {self.__mtu}")
            self.__disable_dplpmtud = True
            return
        if self.__last_dplpmtud_probe_lost:
            self.__lost_dplpmtud_probe_sizes.append(self.__last_dplpmtud_probe_size)
            self.__lost_dplpmtud_probe_sizes.sort()
            self.__lost_dplpmtud_probe_sizes = self.__lost_dplpmtud_probe_sizes[
                : self.__max_lost_probes
            ]
            if len(self.__lost_dplpmtud_probe_sizes) >= self.__max_lost_probes:
                self.__high_mtu = min(self.__high_mtu, self.__lost_dplpmtud_probe_sizes[-1])
        else:
            self.__low_mtu = max(self.__low_mtu, self.__last_dplpmtud_probe_size)
            self.__mtu = max(self.__mtu, self.__low_mtu)
            self.__lost_dplpmtud_probe_sizes = [
                size
                for size in self.__lost_dplpmtud_probe_sizes
                if size > self.__last_dplpmtud_probe_size
            ]
        while True:
            if self.__last_dplpmtud_probe_lost:
                size: int = (
                    self.__low_mtu + min(self.__lost_dplpmtud_probe_sizes[0], self.__high_mtu)
                ) // 2
            else:
                size: int = (self.__low_mtu + self.__high_mtu) // 2
            padding_size: int = size - DATAGRAM_SIZE_OFFSET - self.__checksum_size - 1 - 4 - 2
            padding: bytes = compat.randbytes(padding_size)
            probe_id: bytes = compat.randbytes(4)
            try:
                self.__transceiver.send(
                    PacketTypes.PMTUD_PROBE + probe_id + size.to_bytes(2, "big") + padding
                )
                break
            except MessageTooLong:
                logger.debug(
                    f"Got message too long error when sending DPLPMTUD message of size:{size}, updating MTU"
                )
                new_mtu: int = self.__transceiver.mtu
                self.__high_mtu = min(self.__high_mtu, new_mtu)
                self.__low_mtu = min(self.__low_mtu, new_mtu)
                if self.__high_mtu < self.__min_mtu:
                    logger.warning(
                        f"OS determined path MTU is lower that what the application is designed support, this will lead to degraded performance. Required MTU: {self.__min_mtu} Socket MTU: {self.__high_mtu}"
                    )
                    self.__disable_dplpmtud = True
                    self.__transceiver.set_pmtud(False)
                    self.__mtu = self.__min_mtu
                    break
                logger.info(f"OS updated path MTU, new MTU: {new_mtu}, re-sending probe")
                continue
        self.__last_dplpmtud_probe_id = probe_id
        self.__last_dplpmtud_probe_lost = True
        self.__last_dplpmtud_probe_size = size

    def __cleanup_packets_tracker(self) -> None:
        to_deletes: List[int] = []
        gap: int = 0
        timeout: float = self.__get_packets_tracker_timeout()
        for i, (packet_number, packet_data) in enumerate(self.__packets.items()):
            if i >= CLEANUP_MIN_CHECK_COUNT and gap > CLEANUP_MAX_GAP:
                break
            if (
                packet_data.acknowledged
                and time.perf_counter() - packet_data.timestamps[-1] > timeout
            ):
                to_deletes.append(packet_number)
                gap = 0
            else:
                gap += 1
        for packet_number in to_deletes:
            del self.__packets[packet_number]

    def __retransmit(self) -> None:
        for packet_number, packet_data in self.__packets.items():
            if packet_data.acknowledged:
                continue
            if packet_data.confirm_lost:
                logger.debug(
                    f"Packet #{packet_number - self.__first_packet_number} exceeded reordering threshold, retransmitting"
                )
            elif time.perf_counter() - packet_data.timestamps[-1] > self.__get_timeout():
                logger.debug(
                    f"Packet #{packet_number - self.__first_packet_number} exceeded timeout, retransmitting"
                )
            else:
                continue
            self.__wait_for_pace()
            transmission_number: int = len(packet_data.timestamps)
            while True:
                try:
                    self.__transceiver.send(
                        PacketTypes.DATA
                        + packet_number.to_bytes(6, "big")
                        + transmission_number.to_bytes(2, "big")
                        + self.__data[packet_data.start : packet_data.start + packet_data.size]
                    )
                    break
                except MessageTooLong:
                    logger.warning(
                        "Path MTU was reduced! This is unsupported for retransmission in no fragment mode, enabling IP fragmentation"
                    )
                    new_mtu: int = self.__transceiver.mtu
                    self.__disable_dplpmtud = True
                    self.__transceiver.set_pmtud(False)
                    self.__mtu = max(self.__min_mtu, new_mtu)
                    continue
            packet_data.timestamps.append(time.perf_counter())
            packet_data.confirm_lost = False
            logger.debug(
                f"Retransmitted packet #{packet_number - self.__first_packet_number} successfully"
            )
            self.__update_loss_stats(True)

    def send(self, data: bytes) -> None:
        self.__data: bytes = data
        self.__data_size: int = len(data)
        self.__transmitted: int = 0  # bytes
        self.__received: int = 0  # bytes
        self.__packets: Dict[int, PacketData] = {}
        self.__inflight: int = 0  # bytes

        self.__last_dplpmtud_performed_at: float = -1.0
        self.__last_dplpmtud_probe_size: int = 0
        self.__last_dplpmtud_probe_id: bytes = bytes()
        self.__last_dplpmtud_probe_lost: bool = False
        self.__lost_dplpmtud_probe_sizes: List[int] = []

        start_time: float = time.perf_counter()
        self.__init_connection(self.__data_size)
        self.__last_info_log_message: float = -1.0

        try:
            while True:
                self.__receive_all()
                self.__log_info()
                if (
                    not self.__disable_dplpmtud
                    and time.perf_counter() - self.__last_dplpmtud_performed_at
                    > self.__get_dplpmtud_interval()
                ):
                    self.__dplpmtud()
                    self.__last_dplpmtud_performed_at = time.perf_counter()
                self.__cleanup_packets_tracker()
                self.__retransmit()
                if self.__received >= self.__data_size:
                    logger.info("All data successfully received, terminating connection")
                    raise ConnectionEnding("All data received and acknowledged")
                if self.__inflight >= self.__remote_window_size:
                    continue
                if self.__transmitted >= self.__data_size:
                    continue
                self.__wait_for_pace()
                packet_number: int = self.__get_packet_number()
                while True:
                    data_size: int = min(
                        self.__get_max_data_in_packet(), self.__data_size - self.__transmitted
                    )
                    transmission_number: int = 0
                    try:
                        self.__transceiver.send(
                            PacketTypes.DATA
                            + packet_number.to_bytes(6, "big")
                            + transmission_number.to_bytes(2, "big")
                            + self.__data[self.__transmitted : self.__transmitted + data_size]
                        )
                        break
                    except MessageTooLong:
                        logger.warning(
                            "Path MTU was reduced! Updating MTU and reseting DPLPMTUD controller"
                        )
                        new_mtu: int = self.__transceiver.mtu
                        self.__high_mtu = min(self.__high_mtu, new_mtu)
                        self.__low_mtu = min(self.__low_mtu, new_mtu)
                        self.__mtu = min(self.__mtu, new_mtu)
                        if self.__high_mtu < self.__min_mtu:
                            logger.warning(
                                f"OS determined path MTU is lower that what the application is designed support, this will lead to degraded performance. Required MTU: {self.__min_mtu} Socket MTU: {self.__high_mtu}"
                            )
                            self.__disable_dplpmtud = True
                            self.__transceiver.set_pmtud(False)
                            self.__mtu = self.__min_mtu
                            continue
                        self.__lost_dplpmtud_probe_sizes = []
                        continue
                self.__packets[packet_number] = PacketData(
                    self.__transmitted, data_size, False, False, [time.perf_counter()], set()
                )
                self.__transmitted += data_size
                self.__inflight += data_size
                logger.debug(
                    f"Sent packet #{packet_number - self.__first_packet_number}, Start: {self.__transmitted}, Size: {data_size}"
                )
        except ConnectionEnding:
            self.__log_info(True)
            while True:
                logger.debug("Sending FIN packet")
                self.__transceiver.send(PacketTypes.FIN)
                start: float = time.perf_counter()
                while time.perf_counter() - start < 0.1:
                    try:
                        resp = self.__transceiver.recv(0)
                        resp_type = resp[0:1]
                        if resp_type == PacketTypes.FIN_ACK:
                            logger.debug("Received FIN-ACK packet, acknowledging")
                            self.__transceiver.send(PacketTypes.FIN_ACK)
                            self.__transceiver.close()
                            logger.info("Connection terminated")
                            logger.info(
                                f"Transmission took {time.perf_counter() - start_time:.3f} s."
                            )
                            return
                    except TimeoutError:
                        continue
