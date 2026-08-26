// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// This file has been auto-generated. Do not edit by hand.
// Instead open Developer Command prompt and run: TextTransform FileName.tt
// Or set AllowTlsCipherSuiteGeneration=true and open VS and edit there directly

// This line is needed so that file compiles both as a T4 template and C# file<#+

#if PRODUCT
namespace System.Net.Security
{
#endif
    [CLSCompliant(false)]
    public enum TlsSupportedGroup : ushort
    {
        /// <summary>
        /// Represents the sect163k1 TLS supported group.
        /// </summary>
        sect163k1 = 0x0001, // rfc8422, rfc9847
        /// <summary>
        /// Represents the sect163r1 TLS supported group.
        /// </summary>
        sect163r1 = 0x0002, // rfc8422, rfc9847
        /// <summary>
        /// Represents the sect163r2 TLS supported group.
        /// </summary>
        sect163r2 = 0x0003, // rfc8422, rfc9847
        /// <summary>
        /// Represents the sect193r1 TLS supported group.
        /// </summary>
        sect193r1 = 0x0004, // rfc8422, rfc9847
        /// <summary>
        /// Represents the sect193r2 TLS supported group.
        /// </summary>
        sect193r2 = 0x0005, // rfc8422, rfc9847
        /// <summary>
        /// Represents the sect233k1 TLS supported group.
        /// </summary>
        sect233k1 = 0x0006, // rfc8422, rfc9847
        /// <summary>
        /// Represents the sect233r1 TLS supported group.
        /// </summary>
        sect233r1 = 0x0007, // rfc8422, rfc9847
        /// <summary>
        /// Represents the sect239k1 TLS supported group.
        /// </summary>
        sect239k1 = 0x0008, // rfc8422, rfc9847
        /// <summary>
        /// Represents the sect283k1 TLS supported group.
        /// </summary>
        sect283k1 = 0x0009, // rfc8422
        /// <summary>
        /// Represents the sect283r1 TLS supported group.
        /// </summary>
        sect283r1 = 0x000A, // rfc8422
        /// <summary>
        /// Represents the sect409k1 TLS supported group.
        /// </summary>
        sect409k1 = 0x000B, // rfc8422
        /// <summary>
        /// Represents the sect409r1 TLS supported group.
        /// </summary>
        sect409r1 = 0x000C, // rfc8422
        /// <summary>
        /// Represents the sect571k1 TLS supported group.
        /// </summary>
        sect571k1 = 0x000D, // rfc8422
        /// <summary>
        /// Represents the sect571r1 TLS supported group.
        /// </summary>
        sect571r1 = 0x000E, // rfc8422
        /// <summary>
        /// Represents the secp160k1 TLS supported group.
        /// </summary>
        secp160k1 = 0x000F, // rfc8422, rfc9847
        /// <summary>
        /// Represents the secp160r1 TLS supported group.
        /// </summary>
        secp160r1 = 0x0010, // rfc8422, rfc9847
        /// <summary>
        /// Represents the secp160r2 TLS supported group.
        /// </summary>
        secp160r2 = 0x0011, // rfc8422, rfc9847
        /// <summary>
        /// Represents the secp192k1 TLS supported group.
        /// </summary>
        secp192k1 = 0x0012, // rfc8422, rfc9847
        /// <summary>
        /// Represents the secp192r1 TLS supported group.
        /// </summary>
        secp192r1 = 0x0013, // rfc8422, rfc9847
        /// <summary>
        /// Represents the secp224k1 TLS supported group.
        /// </summary>
        secp224k1 = 0x0014, // rfc8422, rfc9847
        /// <summary>
        /// Represents the secp224r1 TLS supported group.
        /// </summary>
        secp224r1 = 0x0015, // rfc8422, rfc9847
        /// <summary>
        /// Represents the secp256k1 TLS supported group.
        /// </summary>
        secp256k1 = 0x0016, // rfc8422
        /// <summary>
        /// Represents the secp256r1 TLS supported group.
        /// </summary>
        secp256r1 = 0x0017, // rfc8422
        /// <summary>
        /// Represents the secp384r1 TLS supported group.
        /// </summary>
        secp384r1 = 0x0018, // rfc8422
        /// <summary>
        /// Represents the secp521r1 TLS supported group.
        /// </summary>
        secp521r1 = 0x0019, // rfc8422
        /// <summary>
        /// Represents the brainpoolP256r1 TLS supported group.
        /// </summary>
        brainpoolP256r1 = 0x001A, // rfc7027
        /// <summary>
        /// Represents the brainpoolP384r1 TLS supported group.
        /// </summary>
        brainpoolP384r1 = 0x001B, // rfc7027
        /// <summary>
        /// Represents the brainpoolP512r1 TLS supported group.
        /// </summary>
        brainpoolP512r1 = 0x001C, // rfc7027
        /// <summary>
        /// Represents the x25519 TLS supported group.
        /// </summary>
        x25519 = 0x001D, // rfc9846, rfc8422
        /// <summary>
        /// Represents the x448 TLS supported group.
        /// </summary>
        x448 = 0x001E, // rfc9846, rfc8422
        /// <summary>
        /// Represents the brainpoolP256r1tls13 TLS supported group.
        /// </summary>
        brainpoolP256r1tls13 = 0x001F, // rfc8734
        /// <summary>
        /// Represents the brainpoolP384r1tls13 TLS supported group.
        /// </summary>
        brainpoolP384r1tls13 = 0x0020, // rfc8734
        /// <summary>
        /// Represents the brainpoolP512r1tls13 TLS supported group.
        /// </summary>
        brainpoolP512r1tls13 = 0x0021, // rfc8734
        /// <summary>
        /// Represents the GC256A TLS supported group.
        /// </summary>
        GC256A = 0x0022, // rfc9189
        /// <summary>
        /// Represents the GC256B TLS supported group.
        /// </summary>
        GC256B = 0x0023, // rfc9189
        /// <summary>
        /// Represents the GC256C TLS supported group.
        /// </summary>
        GC256C = 0x0024, // rfc9189
        /// <summary>
        /// Represents the GC256D TLS supported group.
        /// </summary>
        GC256D = 0x0025, // rfc9189
        /// <summary>
        /// Represents the GC512A TLS supported group.
        /// </summary>
        GC512A = 0x0026, // rfc9189
        /// <summary>
        /// Represents the GC512B TLS supported group.
        /// </summary>
        GC512B = 0x0027, // rfc9189
        /// <summary>
        /// Represents the GC512C TLS supported group.
        /// </summary>
        GC512C = 0x0028, // rfc9189
        /// <summary>
        /// Represents the curveSM2 TLS supported group.
        /// </summary>
        curveSM2 = 0x0029, // rfc8998
        /// <summary>
        /// Represents the ffdhe2048 TLS supported group.
        /// </summary>
        ffdhe2048 = 0x0100, // rfc7919
        /// <summary>
        /// Represents the ffdhe3072 TLS supported group.
        /// </summary>
        ffdhe3072 = 0x0101, // rfc7919
        /// <summary>
        /// Represents the ffdhe4096 TLS supported group.
        /// </summary>
        ffdhe4096 = 0x0102, // rfc7919
        /// <summary>
        /// Represents the ffdhe6144 TLS supported group.
        /// </summary>
        ffdhe6144 = 0x0103, // rfc7919
        /// <summary>
        /// Represents the ffdhe8192 TLS supported group.
        /// </summary>
        ffdhe8192 = 0x0104, // rfc7919
        /// <summary>
        /// Represents the SecP256r1MLKEM768 TLS supported group.
        /// </summary>
        SecP256r1MLKEM768 = 0x11EB, // rfc10024
        /// <summary>
        /// Represents the X25519MLKEM768 TLS supported group.
        /// </summary>
        X25519MLKEM768 = 0x11EC, // rfc10024
        /// <summary>
        /// Represents the SecP384r1MLKEM1024 TLS supported group.
        /// </summary>
        SecP384r1MLKEM1024 = 0x11ED, // rfc10024
        /// <summary>
        /// Represents the arbitrary_explicit_prime_curves TLS supported group.
        /// </summary>
        arbitrary_explicit_prime_curves = 0xFF01, // rfc8422
        /// <summary>
        /// Represents the arbitrary_explicit_char2_curves TLS supported group.
        /// </summary>
        arbitrary_explicit_char2_curves = 0xFF02, // rfc8422
#if PRODUCT
    }
#endif
}
//#>
