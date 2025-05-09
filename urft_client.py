#!/usr/bin/env python3

import argparse
import datetime
import gzip
import logging
import lzma
import os
from typing import Optional

import compat

import slo

LOG_LEVELS = [logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]

COMPRESSION_LEVEL_CUTOFFS = [
    (8 * 1024 * 1024, 6),  # <= 8 MiB -> level 6
    (12 * 1024 * 1024, 5),  # <= 12 MiB -> level 5
    (16 * 1024 * 1024, 4),  # <= 16 MiB -> level 4
    (32 * 1024 * 1024, 3),  # <= 32 MiB -> level 3
    (48 * 1024 * 1024, 2),  # <= 48 MiB -> level 2
    (64 * 1024 * 1024, 1),  # <= 64 MiB -> level 1
]


logger = logging.getLogger(__name__)


def get_middle_256k(size: int) -> slice:
    middle: int = size // 2
    return slice(max(middle - 128 * 1024, 0), min(middle + 128 * 1024, size))


def estimate_compression_ratio(data: bytes) -> float:
    # Use the middle 256 kiB of the file as a sample
    # gzip should be able to compress this in fractions of a second so speed should not be a concern
    data = data[get_middle_256k(len(data))]
    original_size: int = len(data)
    compressed_data: bytes = gzip.compress(data, compresslevel=6)
    compressed_size: int = len(compressed_data)
    return original_size / compressed_size


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="URFT Client (UDP Reliable File Transfer: Clien (Transmitter))",
        description="Send a file via the SLO protocol to the specified server with guaranteed* delivery. File may be compressed with LZMA2 before sending, use -h to see compression options",
    )
    parser.add_argument(
        "file_path", type=str, help="Path of the file to send, relative to current directory"
    )
    parser.add_argument(
        "server_host", type=str, help="The host of the server to send the file to, IPv4 only"
    )
    parser.add_argument("server_port", type=int, help="The port that the server is listening on")
    parser.add_argument(
        "-c",
        "--compression-level",
        type=int,
        default=None,
        help="Compression level used to compress file before transmission, set to 0 to disable compression. Leave blank for automatic compression level based on file size",
    )
    parser.add_argument(
        "-r",
        "--compression-min-ratio",
        type=float,
        default=1.2,
        help="Minimum estimated compression ratio to perform compression. If estimation compression ratio is less than this, the file will be send uncompressed",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)

    args = parser.parse_args()

    file_path: str = args.file_path
    server_host: str = args.server_host
    server_port: int = args.server_port
    compression_level: Optional[int] = args.compression_level
    minimum_compression_ratio: float = args.compression_min_ratio

    verbosity: int = args.verbose
    verbosity = min(verbosity, len(LOG_LEVELS) - 1)
    log_level = LOG_LEVELS[verbosity]
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d (%(funcName)s) - %(message)s",
    )
    logging.Formatter.formatTime = (
        lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(
            record.created, datetime.timezone.utc
        )
        .astimezone()
        .isoformat(sep="T", timespec="microseconds")
    )

    if not os.path.exists(file_path):
        logger.critical(f"File '{file_path}' does not exist")
        raise FileNotFoundError("File does not exist")

    transmitter: slo.ReliableTransmitter = slo.ReliableTransmitter((server_host, server_port))

    with open(file_path, "rb") as file:
        filename: str = os.path.basename(file_path)
        filename_bytes: bytes = filename.encode("utf-8")
        filename_bytes_length: int = len(filename_bytes)
        if filename_bytes_length > 32767:
            logger.error("File name is longer than 32767 bytes, it will be truncated")
            filename_bytes = filename_bytes[:32767]
            filename_bytes_length = 32767
        file_data: bytes = file.read()
        file_size: int = len(file_data)
        estimated_compression_ratio: float = estimate_compression_ratio(file_data)
        logger.info(
            f"File size: {len(file_data)} bytes, Estimated compression ratio: {estimated_compression_ratio:.3f}"
        )
        compression_level_index: int = compat.bisect_left(
            COMPRESSION_LEVEL_CUTOFFS, file_size, key=lambda x: x[0]
        )
        compress: bool = True
        if not (compression_level is None or 0 < compression_level <= 9):
            logger.info("Skipping compression: user disabled compression")
            compress = False
        elif estimated_compression_ratio < minimum_compression_ratio:
            logger.info("Skipping compression: compression ratio too low")
            compress = False
        elif compression_level_index >= len(COMPRESSION_LEVEL_CUTOFFS):
            logger.info(
                "Skipping compression: file is too big for automatic level compression, specify manual compression level to bypass this"
            )
            compress = False
        if compress:
            if compression_level is None:
                compression_level = COMPRESSION_LEVEL_CUTOFFS[compression_level_index][1]
            logger.info(f"Compressing file with LZMA2 at compression level {compression_level}")
            compressed: bytes = lzma.compress(
                file_data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, preset=compression_level
            )
            compressed_size: int = len(compressed)
            logger.info(
                f"Compressed file size: {compressed_size} bytes ({compressed_size / file_size * 100:.3f}% of original size)"
            )
            # Set the first bit to 1 to indicate file is compressed
            file_header: int = filename_bytes_length | 0x8000
            logger.info("Starting transmission")
            transmitter.send(file_header.to_bytes(2, "big") + filename_bytes + compressed)
        else:
            # Set the first bit to 0 to indicate file is uncompressed
            file_header: int = filename_bytes_length & 0x7FFF
            logger.info("Starting transmission")
            transmitter.send(file_header.to_bytes(2, "big") + filename_bytes + file_data)


if __name__ == "__main__":
    main()
