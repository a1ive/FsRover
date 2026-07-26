# unrar — RAR decompression for Rover

Read-only RAR decoders used by `grub-core/fs/rar.c`.  Covers RAR 1.5,
RAR 2.0, RAR 2.9/3.x and RAR5/RAR7 compressed streams.

## Origin

Ported from **7-Zip 26.02**:

| here | upstream |
|---|---|
| `rar1.c` | `CPP\7zip\Compress\Rar1Decoder.{h,cpp}` |
| `rar2.c` | `CPP\7zip\Compress\Rar2Decoder.{h,cpp}` |
| `rar3.c` | `CPP\7zip\Compress\Rar3Decoder.{h,cpp}`, `Rar3Vm.{h,cpp}` |
| `rar5.c` | `CPP\7zip\Compress\Rar5Decoder.{h,cpp}` |
| `rar_core.{c,h}` | `CPP\7zip\Compress\HuffmanDecoder.h`, `BitmDecoder.h`, `LzOutWindow.{h,cpp}`, `CPP\7zip\Common\{InBuffer,OutBuffer}.{h,cpp}` |

The C++ sources were rewritten as plain C: COM interfaces became the
`rar_decoder` vtable in `unrar.h`, templates became fixed-size structs,
and exceptions became return codes.  The PPMd variant H implementation is
already C upstream and is used unmodified; only its allocator is bridged
to `grub_malloc`/`grub_free`.

## License

7-Zip Copyright (C) 1999-2025 Igor Pavlov.

This part of 7-Zip is licensed under the **GNU LGPL** with the
**unRAR license restriction**:

> The decompression engine for RAR archives was developed using source
> code of unRAR program.  All copyrights to original unRAR code are
> owned by Alexander Roshal.  The license for original unRAR code has
> the following restriction: the unRAR sources cannot be used to
> re-create the RAR compression algorithm, which is proprietary.
> Distribution of modified unRAR sources in separate form or as a part
> of other software is permitted, provided that it is clearly stated in
> the documentation and source comments that the code may not be used
> to develop a RAR (WinRAR) compatible archiver.

Only the **decompression** side is present here.  No RAR compressor is
included, and this code must not be used to build one.

## Not implemented

* The general RAR3 virtual machine interpreter.  Only the six standard
  filters (E8, E8E9, Itanium, RGB, Audio, Delta) are recognised, matching
  7-Zip's default build (`Z7_RARVM_VM_ENABLE` off).  Archives using a
  custom VM program report `RAR_ERR_UNSUP`.
* Encryption (`-p` / `-hp`).  Encrypted entries are rejected by the fs
  driver before any decoder runs.
* Multi-volume reassembly.  Entries split across volumes are rejected.
