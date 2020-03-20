// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Quic.Implementations.Managed.Internal.Tls.OpenSsl;
using System.Net.Quic.Implementations.Managed.Internal.Tls;

namespace System.Net.Quic
{
    public static class QuicImplementationProviders
    {
        public static Implementations.QuicImplementationProvider Managed { get; } = new Implementations.Managed.ManagedQuicImplementationProvider(OpenSslTlsFactory.Instance);
        public static Implementations.QuicImplementationProvider ManagedMockTls { get; } = new Implementations.Managed.ManagedQuicImplementationProvider(MockTlsFactory.Instance);
        public static Implementations.QuicImplementationProvider Default => ManagedMockTls;
    }
}
