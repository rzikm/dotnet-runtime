// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Net.Quic.Implementations.Managed.Internal.Headers;
using System.Net.Quic.Implementations.Managed.Internal.Tls;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace System.Net.Quic.Implementations.Managed.Internal.Sockets
{
    /// <summary>
    ///     Class hosting the background processing thread for a single instance of a QuicConnection.
    /// </summary>
    internal sealed class QuicConnectionContext
    {
        private enum Event
        {
            Timer,
            Receive,
            Update,
        }

        private readonly QuicSocketContext _parent;

        private readonly QuicSocketContext.RecvContext _recvContext;

        private readonly SingleProducerSingleConsumerQueue<DatagramInfo> _recvQueue = new();

        private int _recvQueueEmpty = 1;

        private readonly QuicSocketContext.SendContext _sendContext;

        private Task _backgroundWorkerTask = Task.CompletedTask;

        private readonly QuicReader _reader = new QuicReader(Memory<byte>.Empty);

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
            _timer = new Timer(_ => OnTimer());
        }

        private readonly Timer _timer;

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
            _timer = new Timer(_ => OnTimer());
        }

        private ArrayPool<byte> ArrayPool => _parent.ArrayPool;
        internal ManagedQuicConnection Connection { get; }

        public void OnDatagramReceived(in DatagramInfo datagram)
        {
            _recvQueue.Enqueue(datagram);

            // notify only if the queue was empty before
            if (Interlocked.Exchange(ref _recvQueueEmpty, 0) == 1)
            {
                _eventsChannel.Writer.TryWrite(Event.Receive);
            }
        }

        /// <summary>
        ///     Local endpoint of the socket backing the background processing.
        /// </summary>
        public IPEndPoint LocalEndPoint => _parent.LocalEndPoint;

        /// <summary>
        ///     Remote endpoint of the socket backing the background processing.
        /// </summary>
        public IPEndPoint? RemoteEndPoint => _parent.RemoteEndPoint;

        private Channel<Event> _eventsChannel = Channel.CreateUnbounded<Event>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                AllowSynchronousContinuations = false
            });

        /// <summary>
        ///     Starts the background processing, if not yet started.
        /// </summary>
        public void Start()
        {
            _backgroundWorkerTask = Task.Factory.StartNew(async () =>
            {
                try
                {
                    var reader = _eventsChannel.Reader;

                    while (await reader.WaitToReadAsync().ConfigureAwait(false))
                    {
                        while (reader.TryRead(out var e))
                        {
                            switch (e)
                            {
                                case Event.Receive:
                                    DrainIncomingDatagrams();
                                    break;
                                case Event.Timer:
                                case Event.Update:
                                    SendDatagramIfNeeded();
                                    break;
                            }
                        }

                        UpdateTimer();
                    }
                }
                catch (Exception ex)
                {
                    System.Console.WriteLine($"Exception in QuicConnectionContext background worker: {ex}");
                }
            }, CancellationToken.None, TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            _parent.Start();
        }

        private void OnTimer()
        {
            _eventsChannel.Writer.TryWrite(Event.Timer);
        }

        private void DrainIncomingDatagrams()
        {
            // Reset flag about pending datagrams. it may get set again while we are processing the queue, but that is a
            // benign data race (the next call will simply finish quickly)
            Volatile.Write(ref _recvQueueEmpty, 1);

            while (_recvQueue.TryDequeue(out var datagram))
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
        }

        /// <summary>
        ///     Signals the thread that the pending wait or sleep should be interrupted because the connection has new
        ///     data from the application that need to be processed.
        /// </summary>
        public void WakeUp()
        {
            _eventsChannel.Writer.TryWrite(Event.Update);
        }

        private void SendDatagramIfNeeded()
        {
            if (Connection.GetWriteLevel(Timestamp.Now) != EncryptionLevel.None)
            {
                // TODO: discover path MTU
                byte[]? buffer = ArrayPool.Rent(QuicConstants.MaximumAllowedDatagramSize);
                _writer.Reset(buffer);
                _sendContext.Timestamp = Timestamp.Now;
                Connection.SendData(_writer, out var receiver, _sendContext);

                _parent.SendDatagram(new DatagramInfo(buffer, _writer.BytesWritten, receiver));

                ArrayPool.Return(buffer);
            }
        }

        private void UpdateTimer()
        {
            long timestamp = Connection.GetNextTimerTimestamp();
            var interval = TimeSpan.FromMilliseconds((int)Timestamp.GetMilliseconds(timestamp - Timestamp.Now));
            if (interval > TimeSpan.Zero)
            {
                _timer.Change(interval, Timeout.InfiniteTimeSpan);
            }
            else
            {
                // fire timer immediately
                OnTimer();
            }
        }
    }
}
