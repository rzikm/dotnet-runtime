#nullable enable

using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Quic.Implementations.Managed.Internal.Recovery;
using System.Net.Quic.Implementations.MsQuic.Internal;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed.Internal
{
    /// <summary>
    ///     Structure for gathering received datagrams.
    /// </summary>
    internal class QuicDatagram : IPoolableObject
    {
        public byte[] Buffer { get; } = new byte[QuicConstants.MaximumAllowedDatagramSize];

        public int Length { get; set; }

        public IPEndPoint? EndPoint { get; set; }

        public void Reset() { }
    }

    /// <summary>
    ///     Class responsible for serving a socket for QUIC connections.
    /// </summary>
    internal abstract class QuicSocketContext
    {
        private static readonly Task _infiniteTimeoutTask = new TaskCompletionSource<int>().Task;

        private readonly IPEndPoint? _localEndPoint;
        private readonly bool _isServer;
        private readonly CancellationTokenSource _socketTaskCts;

        private TaskCompletionSource<int> _signalTcs =
            new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        private bool _signalWanted;

        private Task? _backgroundWorkerTask;

        private readonly QuicReader _reader;
        private readonly QuicWriter _writer;

        private readonly SendContext _sendContext;
        private readonly RecvContext _recvContext;

        private readonly byte[] _sendBuffer = new byte[16 * 1024];

        private long _currentTimeout = long.MaxValue;

        protected readonly Socket Socket = new Socket(SocketType.Dgram, ProtocolType.Udp);

        private readonly Channel<QuicDatagram> _recvDatagramChannel =
            Channel.CreateUnbounded<QuicDatagram>(new UnboundedChannelOptions() {SingleReader = true,});
        // private readonly ConcurrentQueue<QuicDatagram> _recvDatagramQueue = new ConcurrentQueue<QuicDatagram>();
        // private readonly ConcurrentQueue<QuicDatagram> _sendDatagramQueue = new ConcurrentQueue<QuicDatagram>();

        private readonly ObjectPool<QuicDatagram> _datagramPool = new ObjectPool<QuicDatagram>(32);

        // private readonly SocketAsyncArgs _sendSocketAsyncEventArgs;
        private readonly SocketAsyncArgs _recvSocketAsyncEventArgs;

        private class SocketAsyncArgs : SocketAsyncEventArgs
        {
            public SocketAsyncArgs(QuicSocketContext context)
            {
                CurrentDatagram = new QuicDatagram();
                _context = context;
            }

            public QuicDatagram CurrentDatagram
            {
                get => _currentDatagram;
                set => _currentDatagram = value ?? throw new ArgumentNullException("value");
            }

            private readonly QuicSocketContext _context;
            private QuicDatagram _currentDatagram;
        }

        // private void OnAsyncSendCompleted(SocketAsyncArgs args)
        // {
        //     FinishAsyncSendOperation(args);
        //
        //     // kick off next operation
        //     StartAsyncSendOperation(args);
        // }
        //
        // private void FinishAsyncSendOperation(SocketAsyncArgs args)
        // {
        //     _datagramPool.Return(args.CurrentDatagram);
        // }
        //
        // private void StartAsyncSendOperation(SocketAsyncArgs args)
        // {
        // }

        private void OnAsyncRecvCompleted(SocketAsyncArgs args)
        {
            FinishAsyncRecvOperation(args);

            if (args.SocketError != SocketError.OperationAborted)
            {
                // kick off next operation
                StartAsyncRecvOperation(args);
            }
        }

        private void FinishAsyncRecvOperation(SocketAsyncArgs args)
        {
            args.CurrentDatagram.Length = args.BytesTransferred;
            args.CurrentDatagram.EndPoint = (IPEndPoint) args.RemoteEndPoint!;

            // should always succeed on unbounded channel
            _recvDatagramChannel.Writer.TryWrite(args.CurrentDatagram);

            args.CurrentDatagram = _datagramPool.Rent();
        }

        private void StartAsyncRecvOperation(SocketAsyncArgs args)
        {
            bool ioPending;

            do
            {
                args.SetBuffer(args.CurrentDatagram.Buffer);

                if (Socket.Connected)
                {
                    ioPending = Socket.ReceiveAsync(args);
                }
                else
                {
                    Debug.Assert(_isServer);

                    // not connected implies server, use listening endpoint
                    args.RemoteEndPoint = _localEndPoint!;
                    ioPending = Socket.ReceiveFromAsync(args);
                }

                if (!ioPending)
                {
                    // finished synchronously, process and repeat
                    FinishAsyncRecvOperation(args);
                }
            } while (!ioPending);
        }

        protected QuicSocketContext(IPEndPoint? localEndPoint, IPEndPoint? remoteEndPoint, bool isServer)
        {
            _localEndPoint = localEndPoint;
            _isServer = isServer;

            _socketTaskCts = new CancellationTokenSource();

            _reader = new QuicReader();
            _writer = new QuicWriter();

            var sentPacketPool = new ObjectPool<SentPacket>(256);
            _sendContext = new SendContext(sentPacketPool);
            _recvContext = new RecvContext(sentPacketPool);

            _recvSocketAsyncEventArgs = new SocketAsyncArgs(this);
            // _sendSocketAsyncEventArgs = new SocketAsyncArgs(this);

            _recvSocketAsyncEventArgs.Completed += (s, e) => OnAsyncRecvCompleted((SocketAsyncArgs)e);
            // _sendSocketAsyncEventArgs.Completed += (s, e) => OnAsyncSendCompleted();

            Socket.ExclusiveAddressUse = false;

            if (localEndPoint != null)
            {
                Socket.Bind(localEndPoint);
            }

            if (remoteEndPoint != null)
            {
                Socket.Connect(remoteEndPoint);
            }

            Socket.Blocking = false;
        }

        public IPEndPoint LocalEndPoint => (IPEndPoint)Socket.LocalEndPoint!;

        internal void Start()
        {
            if (_backgroundWorkerTask != null)
            {
                return;
            }

            // TODO-RZ: Find out why I can't use RuntimeInformation when building inside .NET Runtime
#if FEATURE_QUIC_STANDALONE
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
#endif
            {
                // disable exception when client forcibly closes the socket.
                // https://stackoverflow.com/questions/38191968/c-sharp-udp-an-existing-connection-was-forcibly-closed-by-the-remote-host

                const int SIO_UDP_CONNRESET = -1744830452;
                Socket.IOControl(
                    (IOControlCode)SIO_UDP_CONNRESET,
                    new byte[] { 0, 0, 0, 0 },
                    null
                );
            }

            _backgroundWorkerTask = Task.Run(BackgroundWorker);
        }

        protected void Stop()
        {
            _socketTaskCts.Cancel();
            // if (_backgroundWorkerTask == null)
            // {
                // Socket.Dispose();
            // }
        }

        /// <summary>
        ///     Used to signal the thread that one of the connections has data to send.
        /// </summary>
        internal void Ping()
        {
            _signalWanted = true;
            _signalTcs.TrySetResult(0);
        }

        protected void Update(ManagedQuicConnection connection, QuicConnectionState previousState)
        {
            // TODO-RZ: I would like to have unbound loop there, but this might loop indefinitely
            for (int i = 0; i < 2; i++)
            {
                _writer.Reset(_sendBuffer);
                _sendContext.Timestamp = Timestamp.Now;
                _sendContext.SentPacket.Reset();
                connection.SendData(_writer, out var receiver, _sendContext);

                if (_writer.BytesWritten > 0)
                {
                    if (NetEventSource.IsEnabled) NetEventSource.DatagramSent(connection, _writer.Buffer.Span.Slice(0, _writer.BytesWritten));

                    SendTo(_sendBuffer, _writer.BytesWritten, receiver!);
                }

                var newState = connection.ConnectionState;
                if (newState != previousState && OnConnectionStateChanged(connection, newState) ||
                    _writer.BytesWritten == 0)
                {
                    break;
                }

                previousState = newState;

            }
        }

        protected void Update(ManagedQuicConnection connection)
        {
            Update(connection, connection.ConnectionState);
        }

        protected void UpdateTimeout(long timestamp)
        {
            _currentTimeout = Math.Min(_currentTimeout, timestamp);
        }

        protected abstract ManagedQuicConnection? FindConnection(QuicReader reader, IPEndPoint sender);

        private void DoReceive(Memory<byte> datagram, IPEndPoint sender)
        {
            // process only datagrams big enough to contain valid QUIC packets
            if (datagram.Length < QuicConstants.MinimumPacketSize)
            {
                return;
            }

            _reader.Reset(datagram);

            var connection = FindConnection(_reader, sender);
            if (connection != null)
            {
                if (NetEventSource.IsEnabled) NetEventSource.DatagramReceived(connection, _reader.Buffer.Span);

                var previousState = connection.ConnectionState;
                _recvContext.Timestamp = Timestamp.Now;
                connection.ReceiveData(_reader, sender, _recvContext);

                if (connection.GetWriteLevel(_recvContext.Timestamp) != EncryptionLevel.None)
                {
                    // the connection has some data to send in response
                    Update(connection, previousState);
                }
                else
                {
                    // just check if the datagram changed connection state.
                    var newState = connection.ConnectionState;
                    if (newState != previousState)
                    {
                        OnConnectionStateChanged(connection, newState);
                    }
                }

                UpdateTimeout(connection.GetNextTimerTimestamp());
            }
        }

        private void DoSignal()
        {
            _signalWanted = false;
            OnSignal();
        }

        private void DoTimeout()
        {
            long now = Timestamp.Now;

            // The timer might not fire exactly on time, so we need to make sure it is not just below the
            // timer value so that the actual logic in Connection gets executed.
            Debug.Assert(Timestamp.GetMilliseconds(_currentTimeout - now) <= 5);
            now = Math.Max(now, _currentTimeout);

            // clear previous timeout
            _currentTimeout = long.MaxValue;
            OnTimeout(now);
        }

        protected abstract void OnSignal();

        protected abstract void OnTimeout(long now);

        /// <summary>
        ///     Called when a connections <see cref="ManagedQuicConnection.ConnectionState"/> changes.
        /// </summary>
        /// <param name="connection">The connection.</param>
        /// <param name="newState">The new state of the connection.</param>
        /// <returns>True if the processing of the connection should be stopped.</returns>
        protected abstract bool
            OnConnectionStateChanged(ManagedQuicConnection connection, QuicConnectionState newState);

        protected abstract int ReceiveFrom(byte[] buffer, ref EndPoint sender);

        protected abstract void SendTo(byte[] buffer, int size, EndPoint receiver);

        protected class ReceiveOperationAsyncSocketArgs : SocketAsyncEventArgs
        {
            public ResettableCompletionSource<SocketReceiveFromResult> CompletionSource { get; } = new ResettableCompletionSource<SocketReceiveFromResult>();

            protected override void OnCompleted(SocketAsyncEventArgs e)
            {
                CompletionSource.Complete(
                    new SocketReceiveFromResult()
                    {
                        ReceivedBytes = e.SocketError == SocketError.Success ? e.BytesTransferred : 0,
                        RemoteEndPoint = e.RemoteEndPoint!
                    });
            }
        }

        protected ReceiveOperationAsyncSocketArgs SocketReceiveEventArgs { get; } = new ReceiveOperationAsyncSocketArgs();

        protected abstract bool ReceiveFromAsync(ReceiveOperationAsyncSocketArgs args);

        private ValueTask<SocketReceiveFromResult> ReceiveFromAsync(byte[] buffer, EndPoint sender,
            CancellationToken token)
        {
            // TODO-RZ: utilize cancellation token

            SocketReceiveEventArgs.SetBuffer(buffer);
            SocketReceiveEventArgs.RemoteEndPoint = sender;

            if (ReceiveFromAsync(SocketReceiveEventArgs))
            {
                return SocketReceiveEventArgs.CompletionSource.GetValueTask();
            }

            // operation completed synchronously
            return new ValueTask<SocketReceiveFromResult>(
                new SocketReceiveFromResult
                {
                    ReceivedBytes = SocketReceiveEventArgs.BytesTransferred,
                    RemoteEndPoint = SocketReceiveEventArgs.RemoteEndPoint
                });
        }

        private async Task BackgroundWorker()
        {
            var token = _socketTaskCts.Token;

            StartAsyncRecvOperation(_recvSocketAsyncEventArgs);

            // TODO-RZ: allow timers for multiple connections on server
            long lastAction = long.MinValue;
            try
            {
                while (!token.IsCancellationRequested)
                {
                    bool doTimeout;
                    long now;
                    while (!(doTimeout = _currentTimeout <= (now = Timestamp.Now)) &&
                           !_signalWanted)
                    {
                        if (_recvDatagramChannel.Reader.TryRead(out var datagram))
                        {
                            DoReceive(datagram.Buffer.AsMemory(0, datagram.Length), datagram.EndPoint!);
                            lastAction = now;
                            _datagramPool.Return(datagram);
                        }
                    }

                    if (doTimeout)
                    {
                        DoTimeout();
                        lastAction = now;
                    }

                    if (_signalWanted)
                    {
                        DoSignal();
                        lastAction = now;
                    }

                    const int asyncWaitThreshold = 5;
                    if (Timestamp.GetMilliseconds(now - lastAction) > asyncWaitThreshold)
                    {
                        // there has been no action for some time, stop consuming CPU and wait until an event wakes us
                        int timeoutLength = (int) Timestamp.GetMilliseconds(_currentTimeout - now);
                        Task timeoutTask = _currentTimeout != long.MaxValue
                            ? Task.Delay(timeoutLength, CancellationToken.None)
                            : _infiniteTimeoutTask;

                        // wake-up when a datagram is received
                        var datagramReceiveWait = _recvDatagramChannel.Reader.WaitToReadAsync(token).AsTask();

                        _signalTcs = new TaskCompletionSource<int>();
                        Task signalTask = _signalTcs.Task;

                        if (_signalWanted) // guard against race condition that would deadlock the wait
                        {
                            _signalTcs.TrySetResult(0);
                        }

                        await Task.WhenAny(timeoutTask, datagramReceiveWait, signalTask).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception e)
            {
                if (NetEventSource.IsEnabled) NetEventSource.Error(this, e);
                OnException(e);
            }

            // cleanup everything

            Socket.Close();
            Socket.Dispose();
        }

        protected abstract void OnException(Exception e);

        // TODO-RZ: This function is a slight hack, but the socket context classes will need to be reworked either way
        // protected void ReceiveAllDatagramsForConnection(ManagedQuicConnection connection)
        // {
        //     // sadly, we have to use exception based dispatch, because there is no way to find out that this was the
        //     // last datagram from given endpoint
        //     try
        //     {
        //         while (Socket.Available > 0)
        //         {
        //             EndPoint ep = connection.UnsafeRemoteEndPoint;
        //             int length = Socket.ReceiveFrom(_recvBuffer, ref ep);
        //             Debug.Assert(ep.Equals(connection.UnsafeRemoteEndPoint));
        //
        //             DoReceive(_recvBuffer.AsMemory(0, length), connection.UnsafeRemoteEndPoint);
        //         }
        //     }
        //     catch (SocketException)
        //     {
        //         // "service temporarily unavailable", we are done
        //     }
        // }

        /// <summary>
        ///     Detaches the given connection from this context, the connection will no longer be updated from the
        ///     thread running at this socket.
        /// </summary>
        /// <param name="connection"></param>
        protected internal abstract void DetachConnection(ManagedQuicConnection connection);

        internal class ContextBase
        {
            public ContextBase(ObjectPool<SentPacket> sentPacketPool) => SentPacketPool = sentPacketPool;

            /// <summary>
            ///     Timestamp when the next tick of internal processing was requested.
            /// </summary>
            internal long Timestamp { get; set; }

            internal ObjectPool<SentPacket> SentPacketPool { get; }

            internal void ReturnPacket(SentPacket packet)
            {
                SentPacketPool.Return(packet);
            }
        }

        internal sealed class RecvContext : ContextBase
        {
            /// <summary>
            ///     Flag whether TLS handshake should be incremented at the end of packet processing, perhaps due to
            ///     having received crypto data.
            /// </summary>
            internal bool HandshakeWanted { get; set; }

            public RecvContext(ObjectPool<SentPacket> sentPacketPool) : base(sentPacketPool)
            {
            }
        }

        internal sealed class SendContext : ContextBase
        {
            /// <summary>
            ///     Data about next packet that is to be sent.
            /// </summary>
            internal SentPacket SentPacket { get; private set; } = new SentPacket();

            internal void StartNextPacket()
            {
                SentPacket = SentPacketPool.Rent();
            }

            public SendContext(ObjectPool<SentPacket> sentPacketPool) : base(sentPacketPool)
            {
            }
        }
    }
}
