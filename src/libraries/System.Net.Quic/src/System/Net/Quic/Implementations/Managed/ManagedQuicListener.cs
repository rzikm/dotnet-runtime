// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Sockets;
using System.Net.Quic.Implementations.Managed.Internal.Tls;
using System.Net.Quic.Implementations.Managed.Internal.Tls.OpenSsl;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed
{
    public sealed class ManagedQuicListener : IAsyncDisposable
    {
        public static bool IsSupported => true;
        public static ValueTask<ManagedQuicListener> ListenAsync(QuicListenerOptions options, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(new ManagedQuicListener(options));
        }

        private bool _disposed;

        private readonly ChannelReader<ManagedQuicConnection> _acceptQueue;
        private readonly QuicServerSocketContext _socketContext;

        private ManagedQuicListener(QuicListenerOptions options)
        {
            var listenEndPoint = options.ListenEndPoint ?? new IPEndPoint(IPAddress.Any, 0);

            var channel = Channel.CreateBounded<ManagedQuicConnection>(new BoundedChannelOptions(options.ListenBacklog)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.DropWrite
            });

            _acceptQueue = channel.Reader;
            _socketContext = new QuicServerSocketContext(listenEndPoint, options, channel.Writer, OpenSslTlsFactory.Instance);
            _socketContext.Start();
        }

        public IPEndPoint ListenEndPoint => _socketContext.LocalEndPoint;

        public ValueTask<ManagedQuicConnection> AcceptConnectionAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _acceptQueue.ReadAsync(cancellationToken);
        }

        public ValueTask DisposeAsync()
        {
            if (_disposed) return ValueTask.CompletedTask;

            _disposed = true;

            _socketContext.StopOrOrphan();

            return ValueTask.CompletedTask;
        }
    }
}
