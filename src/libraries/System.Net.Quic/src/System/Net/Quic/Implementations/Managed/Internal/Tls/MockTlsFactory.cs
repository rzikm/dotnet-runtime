// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Managed.Internal.Tls
{
    internal sealed class  MockTlsFactory : TlsFactory
    {
        public static readonly MockTlsFactory Instance = new MockTlsFactory();

        internal override ITls CreateClient(ManagedQuicConnection connection, QuicClientConnectionOptions options,
            TransportParameters localTransportParams) => new MockTls(connection, options, localTransportParams);

        internal override ITls CreateServer(ManagedQuicConnection connection, QuicServerConnectionOptions options,
            TransportParameters localTransportParams) => new MockTls(connection, options, localTransportParams);
    }
}