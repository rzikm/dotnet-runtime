﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Net.Quic.Implementations.Managed.Internal.Headers;
using System.Net.Quic.Implementations.Managed.Internal.Tls;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed.Internal.Sockets
{
    /// <summary>
    ///     Class hosting the background processing thread for a single instance of a QuicConnection.
    /// </summary>
    internal sealed class QuicConnectionContext
    {
        private readonly QuicSocketContext _parent;

        private readonly QuicSocketContext.RecvContext _recvContext;

        // TODO-RZ: maybe bounded channel with drop behavior would be better?
        private readonly Channel<DatagramInfo> _recvQueue = Channel.CreateUnbounded<DatagramInfo>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = true,
                AllowSynchronousContinuations = false
            });

        private readonly QuicSocketContext.SendContext _sendContext;

        private Task _backgroundWorkerTask = Task.CompletedTask;
        private bool _needsUpdate;
        private readonly QuicReader _reader = new QuicReader(Memory<byte>.Empty);

        private long _timer = long.MaxValue;

        private TaskCompletionSource _waitCompletionSource = new TaskCompletionSource();

        private readonly QuicWriter _writer = new QuicWriter(Memory<byte>.Empty);

        public QuicConnectionContext(QuicServerSocketContext parent, EndPoint remoteEndpoint, ReadOnlySpan<byte> odcid, TlsFactory tlsFactory)
        {
            _parent = parent;
            // TODO-RZ: move processing of first packet to Listener and create connection context only after we get the QuicServerConnectionOptions.
            Connection = new ManagedQuicConnection(this, remoteEndpoint, odcid, tlsFactory);
            Connection.SetSocketContext(this);

            // if handshake fails, we need to propagate the error to the listener.AcceptConnectionAsync
            // TODO-RZ: this is far from ideal, and should be revisited together with the rest of the
            // server-side handshake code
            Connection._connectTcs.GetTask().AsTask().ContinueWith(t =>
            {
                if (t.IsFaulted)
                {
                    parent.OnConnectionHandshakeFailed(t.Exception!.InnerException!);
                }
            }, TaskScheduler.Default);

            ObjectPool<SentPacket>? sentPacketPool = new ObjectPool<SentPacket>(256);
            _sendContext = new QuicSocketContext.SendContext(sentPacketPool);
            _recvContext = new QuicSocketContext.RecvContext(sentPacketPool);
        }

        public QuicServerConnectionOptions GetServerConnectionOptions(ManagedQuicConnection connection)
        {
            try
            {
                return ((QuicServerSocketContext)_parent).ListenerOptions.ConnectionOptionsCallback(connection, default, default).AsTask().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                throw new QuicException(QuicError.CallbackError, null, "ConnectionOptionsCallback failed.", ex);
            }
        }

        public QuicConnectionContext(SingleConnectionSocketContext parent, ManagedQuicConnection connection)
        {
            _parent = parent;
            Connection = connection;

            ObjectPool<SentPacket>? sentPacketPool = new ObjectPool<SentPacket>(256);
            _sendContext = new QuicSocketContext.SendContext(sentPacketPool);
            _recvContext = new QuicSocketContext.RecvContext(sentPacketPool);
        }

        private ArrayPool<byte> ArrayPool => _parent.ArrayPool;
        internal ManagedQuicConnection Connection { get; }

        internal ChannelWriter<DatagramInfo> IncomingDatagramWriter => _recvQueue.Writer;

        /// <summary>
        ///     Local endpoint of the socket backing the background processing.
        /// </summary>
        public IPEndPoint LocalEndPoint => _parent.LocalEndPoint;

        /// <summary>
        ///     Remote endpoint of the socket backing the background processing.
        /// </summary>
        public IPEndPoint? RemoteEndPoint => _parent.RemoteEndPoint;

        private void DoReceiveDatagram(DatagramInfo datagram)
        {
            _reader.Reset(datagram.Buffer.AsMemory(0, datagram.Length));

            QuicConnectionState previousState = Connection.ConnectionState;
            _recvContext.Timestamp = Timestamp.Now;
            Connection.ReceiveData(_reader, datagram.RemoteEndpoint, _recvContext);
            // the array pools are shared
            ArrayPool.Return(datagram.Buffer);

            QuicConnectionState newState = Connection.ConnectionState;
            if (newState != previousState)
            {
                _parent.OnConnectionStateChanged(Connection, newState);
            }
        }

        /// <summary>
        ///     Starts the background processing, if not yet started.
        /// </summary>
        public void Start()
        {
            _backgroundWorkerTask = Task.Factory.StartNew(Run, CancellationToken.None, TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            _parent.Start();
        }

        /// <summary>
        ///     Signals the thread that the pending wait or sleep should be interrupted because the connection has new
        ///     data from the application that need to be processed.
        /// </summary>
        public void WakeUp()
        {
            _waitCompletionSource.TrySetResult();
            _needsUpdate = true;
        }

        private async Task Run()
        {
            while (Connection.ConnectionState != QuicConnectionState.Closed)
            {
                if (Timestamp.Now >= _timer)
                {
                    QuicConnectionState previousState = Connection.ConnectionState;
                    Connection.OnTimeout(Timestamp.Now);
                    QuicConnectionState newState = Connection.ConnectionState;
                    if (newState != previousState)
                    {
                        _parent.OnConnectionStateChanged(Connection, newState);
                    }
                }

                while (_recvQueue.Reader.TryRead(out DatagramInfo datagram))
                {
                    DoReceiveDatagram(datagram);
                }

                if (Connection.GetWriteLevel(Timestamp.Now) != EncryptionLevel.None)
                {
                    _needsUpdate = false;
                    // TODO: discover path MTU
                    byte[]? buffer = ArrayPool.Rent(QuicConstants.MaximumAllowedDatagramSize);
                    _writer.Reset(buffer);
                    _sendContext.Timestamp = Timestamp.Now;
                    Connection.SendData(_writer, out var receiver, _sendContext);

                    _parent.SendDatagram(new DatagramInfo(buffer, _writer.BytesWritten, receiver));

                    ArrayPool.Return(buffer);
                }

                long now = Timestamp.Now;
                _timer = Connection.GetNextTimerTimestamp();
                if (now < _timer)
                {
                    // asynchronously wait until either the timer expires or we receive a new datagram
                    if (_waitCompletionSource.Task.IsCompleted)
                    {
                        _waitCompletionSource =
                            new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    }

                    // protection against race conditions (flag set just after last update finished)
                    if (!_needsUpdate)
                    {
                        CancellationTokenSource cts = new CancellationTokenSource();
                        Task<bool>? read = _recvQueue.Reader.WaitToReadAsync(cts.Token).AsTask();
                        using CancellationTokenRegistration registration = cts.Token.Register(static s =>
                        {
                            ((TaskCompletionSource?)s)?.TrySetResult();
                        }, _waitCompletionSource);

                        if (_timer < long.MaxValue)
                        {
                            cts.CancelAfter((int)Timestamp.GetMilliseconds(_timer - now));
                        }

                        await Task.WhenAny(read, _waitCompletionSource.Task).ConfigureAwait(false);
                        cts.Cancel();
                    }
                }
            }
        }
    }
}
