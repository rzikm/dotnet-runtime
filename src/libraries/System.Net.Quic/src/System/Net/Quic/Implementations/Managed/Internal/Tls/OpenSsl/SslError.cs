// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Managed.Internal.Tls.OpenSsl
{
    internal enum SslError
    {
        None = 0,
        Ssl = 1,
        WantRead = 2,
        WantWrite = 3,
        WantX509Lookup = 4,
        Syscall = 5,
        ZeroReturn = 6,
        WantConnect = 7,
        WantAccept = 8,
        WantAsync = 9,
        WantAsyncJob = 10,
        WantClientHelloCb = 11
    }
}
