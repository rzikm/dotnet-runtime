#nullable enable

using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Quic.Implementations.MsQuic.Internal;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed.Internal
{
    /// <summary>
    ///     Class responsible for serving a socket for QUIC connections.
    /// </summary>
    internal abstract class QuicSocketContext
    {
        private static readonly Task _infiniteTimeoutTask = new TaskCompletionSource<int>().Task;

        private readonly IPEndPoint? _localEndPoint;
        private readonly IPEndPoint? _remoteEndPoint;
        private readonly bool _isServer;
        private readonly CancellationTokenSource _socketTaskCts;

        private TaskCompletionSource<int> _signalTcs =
            new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        private bool _signalWanted;
        private bool _started;

        private readonly byte[] _sendBuffer = new byte[QuicConstants.MaximumAllowedDatagramSize];
        private readonly byte[] _recvBuffer = new byte[QuicConstants.MaximumAllowedDatagramSize];

        private readonly ManualResetEventSlim _wakeUpEvent = new ManualResetEventSlim();

        private Task? _backgroundWorkerTask;

        private long _currentTimeout = long.MaxValue;

        protected readonly Socket Socket = new Socket(SocketType.Dgram, ProtocolType.Udp);

        protected readonly ConcurrentQueue<(byte[], int, IPEndPoint)> _recvQueue = new ConcurrentQueue<(byte[], int, IPEndPoint)>();

        protected QuicSocketContext(IPEndPoint? localEndPoint, IPEndPoint? remoteEndPoint, bool isServer)
        {
            _localEndPoint = localEndPoint;
            _remoteEndPoint = remoteEndPoint;
            _isServer = isServer;

            _socketTaskCts = new CancellationTokenSource();

            SetupSocket(localEndPoint, remoteEndPoint);

            SocketReceiveEventArgs = new ReceiveOperationAsyncSocketArgs(this);
        }

        private void SetupSocket(IPEndPoint? localEndPoint, IPEndPoint? remoteEndPoint)
        {
            Socket.UseOnlyOverlappedIO = true;

            if (localEndPoint != null)
            {
                Socket.Bind(localEndPoint);
            }

            if (remoteEndPoint != null)
            {
                Socket.Connect(remoteEndPoint);
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
                    (IOControlCode) SIO_UDP_CONNRESET,
                    new byte[] {0, 0, 0, 0},
                    null
                );
            }
        }

        public IPEndPoint LocalEndPoint => (IPEndPoint)Socket.LocalEndPoint!;

        internal void Start()
        {
            if (_backgroundWorkerTask != null)
            {
                return;
            }

            _started = true;
            _backgroundWorkerTask = Task.Run(BackgroundWorker);
        }

        protected void Stop()
        {
            _socketTaskCts.Cancel();

            // if never started also cleanup the socket, since the background worker will not do that
            if (!_started)
            {
                Socket.Dispose();
            }
        }

        /// <summary>
        ///     Used to signal the thread that one of the connections has data to send.
        /// </summary>
        internal void Ping()
        {
            _signalWanted = true;

            // wake the spinning thread if necessary
            _wakeUpEvent.Set();
        }

        private void UpdateUnsafe(ManagedQuicConnection connection, QuicConnectionState previousState)
        {
            // TODO-RZ: I would like to have unbound loop there, but this might loop indefinitely
            for (int i = 0; i < 2; i++)
            {
                long now = Timestamp.Now;
                int written = connection.SendData(_sendBuffer, out var receiver, now);

                if (written > 0)
                {
                    if (NetEventSource.IsEnabled) NetEventSource.DatagramSent(connection, _sendBuffer.AsSpan(0, written));

                    SendTo(_sendBuffer, written, receiver!);
                }

                var newState = connection.ConnectionState;
                if (newState != previousState && OnConnectionStateChanged(connection, newState) ||
                    written == 0)
                {
                    break;
                }

                previousState = newState;
            }
        }

        protected void Update(ManagedQuicConnection connection, QuicConnectionState previousState)
        {
            // lock (connection)
            {
                UpdateUnsafe(connection, previousState);
            }
        }

        protected void Update(ManagedQuicConnection connection)
        {
            // lock (connection)
            {
                UpdateUnsafe(connection, connection.ConnectionState);
            }
        }

        protected void UpdateTimeout(long timestamp)
        {
            _currentTimeout = Math.Min(_currentTimeout, timestamp);
            _wakeUpEvent.Set();
        }

        protected abstract ManagedQuicConnection? FindConnection(Memory<byte> reader, IPEndPoint sender);

        private void DoReceive(Memory<byte> datagram, IPEndPoint sender)
        {
            // process only datagrams big enough to contain valid QUIC packets
            if (datagram.Length < QuicConstants.MinimumPacketSize)
            {
                return;
            }

            var connection = FindConnection(datagram, sender);
            if (connection != null)
            {
                // lock (connection)
                {
                    if (connection.ConnectionState >= QuicConnectionState.Closing)
                    {
                        // while waiting, the connection was closed
                        return;
                    }

                    if (NetEventSource.IsEnabled) NetEventSource.DatagramReceived(connection, datagram.Span);

                    var previousState = connection.ConnectionState;

                    long now = Timestamp.Now;
                    connection.ReceiveData(datagram, sender, now);

                    if (connection.GetWriteLevel(now) != EncryptionLevel.None)
                    {
                        // the connection has some data to send in response
                        UpdateUnsafe(connection, previousState);
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
            private readonly QuicSocketContext context;

            public ReceiveOperationAsyncSocketArgs(QuicSocketContext context) => this.context = context;

            public ResettableCompletionSource<SocketReceiveFromResult> CompletionSource { get; } = new ResettableCompletionSource<SocketReceiveFromResult>();

            protected override void OnCompleted(SocketAsyncEventArgs e)
            {
                context.OnDatagramReceived(e);
            }
        }

        private void OnDatagramReceived(SocketAsyncEventArgs e, bool skipFirstReceive = false)
        {
            bool ioPending;
            do
            {
                var buffer = e.Buffer;
                int bytesTransferred = e.BytesTransferred;
                var endpoint = (IPEndPoint)e.RemoteEndPoint!;

                // break from the loop when shutdown requested
                ioPending = _socketTaskCts.IsCancellationRequested || DispatchAsyncReceive(e);

                if (!skipFirstReceive)
                {
                    _recvQueue.Enqueue((buffer!, bytesTransferred, endpoint));
                    _wakeUpEvent.Set();
                }

                skipFirstReceive = false;

            } while (!ioPending);
        }

        private bool DispatchAsyncReceive(SocketAsyncEventArgs e)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(QuicConstants.MaximumAllowedDatagramSize);
            e.SetBuffer(buffer, 0, buffer.Length);
            if (_remoteEndPoint != null)
            {
                Debug.Assert(Socket.Connected);
                // optimization: use overload without explicit address
                e.RemoteEndPoint = _remoteEndPoint;
                return Socket.ReceiveAsync(e);
            }

            e.RemoteEndPoint = _localEndPoint;
            return Socket.ReceiveFromAsync(e);
        }

        protected ReceiveOperationAsyncSocketArgs SocketReceiveEventArgs { get; }

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

            // Start receiving loop
            OnDatagramReceived(SocketReceiveEventArgs, true);

            // TODO-RZ: allow timers for multiple connections on server
            long lastAction = long.MinValue;
            try
            {
                while (!token.IsCancellationRequested)
                {
                    long now;
                    bool doTimeout = _currentTimeout <= (now = Timestamp.Now);

                    while (_recvQueue.TryDequeue(out var dgram))
                    {
                        var (buffer, bytes, sender) = dgram;
                        DoReceive(buffer.AsMemory(0, bytes), sender);
                        ArrayPool<byte>.Shared.Return(buffer);
                    }

                    if (doTimeout)
                    {
                        DoTimeout();
                        // lastAction = now;
                    }

                    if (_signalWanted)
                    {
                        DoSignal();
                        // lastAction = now;
                    }

                    // go to sleep until next action
                    int timeoutLength = (int) Timestamp.GetMilliseconds(_currentTimeout - now);
                    if (timeoutLength > 10)
                    {
                        _wakeUpEvent.Wait(timeoutLength);
                        _wakeUpEvent.Reset();
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
