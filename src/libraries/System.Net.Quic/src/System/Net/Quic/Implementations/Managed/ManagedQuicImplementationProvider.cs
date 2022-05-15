// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Quic.Implementations.Managed.Internal.Tls;

namespace System.Net.Quic.Implementations.Managed
{
    internal sealed class ManagedQuicImplementationProvider : QuicImplementationProvider
    {
        public override bool IsSupported => _tlsFactory is TlsFactory || Interop.OpenSslQuic.IsSupported;

        private readonly TlsFactory _tlsFactory;

        public ManagedQuicImplementationProvider(TlsFactory tlsFactory)
        {
            _tlsFactory = tlsFactory;
        }

        internal override QuicListenerProvider CreateListener(QuicListenerOptions options) => new ManagedQuicListener(options, _tlsFactory);

        internal override QuicConnectionProvider CreateConnection(QuicClientConnectionOptions options) => new ManagedQuicConnection(options, _tlsFactory);
    }
}
