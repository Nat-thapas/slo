#!/usr/bin/env python3

import argparse
import datetime
import logging
import lzma
import os

import slo

LOG_LEVELS = [logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]


logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="URFT Server (UDP Reliable File Transfer: Server (Receiver))",
        description="Receive a file sent via the SLO protocol with guaranteed* delivery",
    )
    parser.add_argument("listen_host", type=str, help="The host to listen/bind to, IPv4 only")
    parser.add_argument("listen_port", type=int, help="The port to listen/bind to")
    parser.add_argument("-v", "--verbose", action="count", default=0)

    args = parser.parse_args()

    listen_host: str = args.listen_host
    listen_port: int = args.listen_port

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

    receiver: slo.ReliableReceiver = slo.ReliableReceiver((listen_host, listen_port))

    data = receiver.recv()

    file_header: int = int.from_bytes(data[0:2], "big")
    is_compressed: bool = bool(0x8000 & file_header)
    filename_length: int = file_header & 0x7FFF
    filename_bytes: bytes = data[2 : 2 + filename_length]
    filename: str = filename_bytes.decode("utf-8")
    file_data: bytes = data[2 + filename_length :]

    if os.path.exists(filename):
        logger.warning(f"File at '{filename}' will be overwritten")

    with open(filename, "wb") as file:
        if is_compressed:
            try:
                logger.info("File is comprssed, decompressing file")
                decompressed: bytes = lzma.decompress(file_data, format=lzma.FORMAT_XZ)
                file.write(decompressed)
            except lzma.LZMAError:
                logger.info("Failed to decompress file, saving raw file data instead")
                file.write(file_data)
        else:
            logger.info("File is uncompressed, saving file")
            file.write(file_data)

    logger.info("File saved")


if __name__ == "__main__":
    main()
