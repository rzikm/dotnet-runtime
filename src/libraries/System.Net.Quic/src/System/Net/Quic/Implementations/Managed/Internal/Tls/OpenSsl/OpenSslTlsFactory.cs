// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Managed.Internal.Tls.OpenSsl
{
    internal sealed class OpenSslTlsFactory : TlsFactory
    {
        public static readonly OpenSslTlsFactory Instance = new OpenSslTlsFactory();

        internal override ITls CreateClient(ManagedQuicConnection connection, QuicClientConnectionOptions options,
            TransportParameters localTransportParams) => new OpenSslTls(connection, options, localTransportParams);

        internal override ITls CreateServer(ManagedQuicConnection connection, QuicServerConnectionOptions options,
            TransportParameters localTransportParams) => new OpenSslTls(connection, options, localTransportParams);
    }
}