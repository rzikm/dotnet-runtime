// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

internal static partial class Interop
{
    internal static partial class Libraries
    {
        internal const string Odbc32 = "libodbc.so.2";
        internal const string MsQuic = "msquic";

        // TODO-RZ : use locally built libs from akamai-openssl-quic
        // internal const string Ssl = "libssl-quic.so.1.1";
        // internal const string Crypto = "libcrypto-quic.so.1.1";
        internal const string Ssl = "/usr/local/lib/libssl.so";
        internal const string Crypto = "/usr/local/lib/libcrypto.so";
    }
}
