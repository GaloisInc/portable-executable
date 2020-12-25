This package implements a parser for Portable Executable (PE) files.  It supports both PE32 and PE32+ (which is an extended version of the format to support 64 bit binaries).  The API is loosely modeled on that exposed by the [elf-edit](https://github.com/GaloisInc/elf-edit) package.  Usage proceeds in two phases:

1. Parse a bytestring into a `PEHeaderInfo` using `decodePEHeaderInfo`, which contains the basic information about the layout of the file (including all of the section offsets)
2. Read the contents of individual sections using `getSection`

The two phases are separate to ensure that the parser can be as robust as possible and return partial information in the face of potentially malformed files.  Errors outside of headers can be ignored safely and without incurring a large up-front invalid parsing cost.
