// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Managed.Internal.Sockets
{
    internal readonly struct DatagramInfo
    {
        public DatagramInfo(byte[] buffer, int length, SocketAddress remoteEndpoint)
        {
            Buffer = buffer;
            Length = length;
            RemoteAddress = remoteEndpoint;
        }

        public byte[] Buffer { get; }
        public int Length { get; }
        public SocketAddress RemoteAddress { get; }
    }
}
