// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Quic.Implementations.Managed.Internal.Sockets;
using System.Net.Quic.Implementations.Managed.Internal.Tls;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed
{
    public sealed class ManagedQuicListener : QuicListener, IAsyncDisposable
    {
        public static new bool IsSupported => true;
        public static new ValueTask<QuicListener> ListenAsync(QuicListenerOptions options, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult((QuicListener)new ManagedQuicListener(options));
        }

        private bool _disposed;

        private readonly ChannelReader<object /* either ManagedQuicConnectin or Exception */> _acceptQueue;
        private readonly QuicServerSocketContext _socketContext;

        private ManagedQuicListener(QuicListenerOptions options)
            : base(true)
        {
            options.Validate(nameof(options));

            var channel = Channel.CreateBounded<object>(new BoundedChannelOptions(options.ListenBacklog)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.DropWrite
            });

            _acceptQueue = channel.Reader;
            _socketContext = new QuicServerSocketContext(options.ListenEndPoint, options, channel.Writer, TlsFactory.Default);
            _socketContext.Start();
        }

        public override IPEndPoint LocalEndPoint => _socketContext.LocalEndPoint;

        public override async ValueTask<QuicConnection> AcceptConnectionAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            try
            {
                var result = await _acceptQueue.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (result is ManagedQuicConnection qc)
                {
                    return qc;
                }

                ExceptionDispatchInfo.Throw((Exception)result);
                throw null; // Never reached.
            }
            catch (ChannelClosedException ex) when (ex.InnerException is not null)
            {
                ExceptionDispatchInfo.Throw(ex.InnerException);
                throw;
            }
        }

        public override ValueTask DisposeAsync()
        {
            if (_disposed) return ValueTask.CompletedTask;

            _disposed = true;

            // TODO: wait until close?
            _socketContext.StopOrOrphan();

            return ValueTask.CompletedTask;
        }
    }
}