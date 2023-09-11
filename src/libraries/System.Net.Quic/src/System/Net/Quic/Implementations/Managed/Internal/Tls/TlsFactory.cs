// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Managed.Internal.Tls
{
    internal abstract class TlsFactory
    {
        internal abstract ITls CreateClient(ManagedQuicConnection connection, QuicClientConnectionOptions options,
            TransportParameters localTransportParams);

        internal abstract ITls CreateServer(ManagedQuicConnection connection, QuicServerConnectionOptions options,
            TransportParameters localTransportParams);
    }
}
