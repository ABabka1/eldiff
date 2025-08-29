import base64
import hashlib
import zlib
from ctypes import (
    CDLL,
    POINTER,
    LittleEndianStructure,
    c_size_t,
    c_ubyte,
    c_uint64,
    cast,
    windll,
    wintypes,
)
from ctypes import (
    Union as CUnion,
)
from pathlib import Path
from typing import List, Optional, Union

# types and flags
DELTA_FLAG_TYPE = c_uint64
DELTA_FLAG_NONE = 0x00000000
DELTA_APPLY_FLAG_ALLOW_PA19 = 0x00000001

# magic values
MAGIC_PA19 = b"PA19"
MAGIC_PA30 = b"PA30"
MAGIC_PA31 = b"PA31"


class DeltaPatchException(Exception):
    pass


# structures
class DELTA_INPUT(LittleEndianStructure):
    class U1(CUnion):
        _fields_ = [("lpcStart", wintypes.LPVOID), ("lpStart", wintypes.LPVOID)]

    _anonymous_ = ("u1",)
    _fields_ = [("u1", U1), ("uSize", c_size_t), ("Editable", wintypes.BOOL)]


class DELTA_OUTPUT(LittleEndianStructure):
    _fields_ = [("lpStart", wintypes.LPVOID), ("uSize", c_size_t)]


class DeltaPatcher(object):
    class DeltaFuncs:
        def __init__(self, msdelta: CDLL):
            def _apply_delta_errcheck(res: wintypes.BOOL, func, args):
                if not res:
                    last_err = windll.kernel32.GetLastError()
                    raise DeltaPatchException(
                        f"ApplyDeltaB failed with GLE = {last_err}"
                    )
                output: DELTA_OUTPUT = args[3]
                # cast the void pointer output to a correctly sized byte array pointer
                # then get the contents and initialize a bytes object
                # this should copy the bytes
                patchbuf = bytes(
                    cast(output.lpStart, POINTER(c_ubyte * output.uSize)).contents
                )
                self.DeltaFree(output.lpStart)
                return patchbuf

            self.ApplyDeltaB = msdelta.ApplyDeltaB
            self.DeltaFree = msdelta.DeltaFree
            self.ApplyDeltaB.argtypes = [
                DELTA_FLAG_TYPE,
                DELTA_INPUT,
                DELTA_INPUT,
                POINTER(DELTA_OUTPUT),
            ]
            self.ApplyDeltaB.restype = wintypes.BOOL
            self.ApplyDeltaB.errcheck = _apply_delta_errcheck
            self.DeltaFree.argtypes = [wintypes.LPVOID]
            self.DeltaFree.restype = wintypes.BOOL

    def __init__(
        self,
        patcher_dll_path: Union[Path, str] = "msdelta.dll",
        buffer: Optional[Union[str, bytes, Path]] = None,
        allow_legacy=False,
    ):
        self.__msdelta = CDLL(patcher_dll_path)
        self.funcs = DeltaPatcher.DeltaFuncs(self.__msdelta)
        self.flags = DELTA_APPLY_FLAG_ALLOW_PA19 if allow_legacy else DELTA_FLAG_NONE
        if isinstance(buffer, (str, Path)):
            buffer = open(buffer, "rb").read()
        self.buffer = buffer or b""

    def apply_all(self, patches: List[Union[str, bytes, Path]]):
        for patch in patches:
            self.apply_delta(patch)

    def apply_delta(self, patch: Union[str, bytes, Path]):
        if isinstance(patch, (str, Path)):
            patch = open(patch, "rb").read()
        # check for the CRC, strip if required
        magics = [MAGIC_PA19, MAGIC_PA30, MAGIC_PA31]
        if (
            zlib.crc32(patch[4:]) == int.from_bytes(patch[:4], "little")
            and patch[4:8] in magics
        ):
            patch = patch[4:]
        if patch[:4] not in magics:
            raise DeltaPatchException(
                "Invalid patch file. Starts with {} instead of acceptable magic values",
                patch[:4].hex(),
            )
        buffer_input = DELTA_INPUT(
            DELTA_INPUT.U1(lpcStart=cast(self.buffer, wintypes.LPVOID)),
            len(self.buffer),
            False,
        )
        patch_input = DELTA_INPUT(
            DELTA_INPUT.U1(lpcStart=cast(patch, wintypes.LPVOID)), len(patch), False
        )
        output = DELTA_OUTPUT()
        self.buffer = self.funcs.ApplyDeltaB(
            self.flags, buffer_input, patch_input, output
        )

    def checksum(self) -> str:
        return base64.b64encode(hashlib.sha256(self.buffer).digest()).decode()

    def __bytes__(self) -> bytes:
        return self.buffer


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    output = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "-i", "--input-file", type=Path, help="File to patch (forward or reverse)"
    )
    mode.add_argument(
        "-n",
        "--null",
        action="store_true",
        default=False,
        help="Create the output file from a null diff "
        "(null diff must be the first one specified)",
    )
    output.add_argument(
        "-o", "--output-file", type=Path, help="Destination to write patched file to"
    )
    output.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="Don't write patch, just see if it would patch"
        "correctly and get the resulting hash",
    )
    ap.add_argument(
        "-l",
        "--legacy",
        action="store_true",
        default=False,
        help="Let the API use the PA19 legacy API (if required)",
    )
    ap.add_argument(
        "-D",
        "--patcher-dll",
        type=Path,
        default="msdelta.dll",
        help="DLL to load and use for patch delta API",
    )
    ap.add_argument("patches", nargs="+", type=Path, help="Patches to apply")
    args = ap.parse_args()

    if not args.dry_run and not args.output_file:
        print("Either specify -d or -o", file=sys.stderr)
        ap.print_help()
        sys.exit(1)

    patcher = DeltaPatcher(args.patcher_dll, args.input_file, args.legacy)
    patcher.apply_all(args.patches)

    print(
        "Applied {} patch{} successfully".format(
            len(args.patches), "es" if len(args.patches) > 1 else ""
        )
    )
    print("Final hash: {}".format(patcher.checksum()))

    if not args.dry_run:
        open(args.output_file, "wb").write(bytes(patcher))
        print(f"Wrote {len(bytes(patcher))} bytes to {args.output_file.resolve()}")