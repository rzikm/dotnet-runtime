// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System.Buffers;
using System.Diagnostics;
using System.Net.Quic.Implementations.Managed.Internal.Headers;
using System.Net.Quic.Implementations.MsQuic.Internal;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed.Internal.Sockets
{
    internal interface IQuicSocketContext
    {
        void Start();

        /// <summary>
        ///     Used to signal the thread that one of the connections has data to send.
        /// </summary>
        void WakeUp();

        IPEndPoint LocalEndPoint { get; }
    }

    /// <summary>
    ///     Class responsible for serving a socket for QUIC connections.
    /// </summary>
    internal abstract class QuicSocketContext
    {
        private static readonly Task _infiniteTimeoutTask = new TaskCompletionSource<int>().Task;

        private readonly EndPoint? _localEndPoint;
        private readonly EndPoint? _remoteEndPoint;
        private readonly bool _isServer;
        private readonly CancellationTokenSource _socketTaskCts;

        private bool _started;

        private Task? _backgroundWorkerTask;

        private readonly Socket Socket = new Socket(SocketType.Dgram, ProtocolType.Udp);

        protected QuicSocketContext(EndPoint? localEndPoint, EndPoint? remoteEndPoint, bool isServer)
        {
            _localEndPoint = localEndPoint;
            _remoteEndPoint = remoteEndPoint;

            _isServer = isServer;

            _socketTaskCts = new CancellationTokenSource();

            SetupSocket(localEndPoint, remoteEndPoint);
        }

        private void SetupSocket(EndPoint? localEndPoint, EndPoint? remoteEndPoint)
        {
            if (Socket.AddressFamily == AddressFamily.InterNetwork)
            {
                Socket.DontFragment = true;
            }

            if (localEndPoint != null)
            {
                Socket.Bind(localEndPoint);
            }

            if (remoteEndPoint != null)
            {
                Socket.Connect(remoteEndPoint);
            }

#if WINDOWS
            // disable exception when client forcibly closes the socket.
            // https://stackoverflow.com/questions/38191968/c-sharp-udp-an-existing-connection-was-forcibly-closed-by-the-remote-host

            const int SIO_UDP_CONNRESET = -1744830452;
                Socket.IOControl(
                (IOControlCode)SIO_UDP_CONNRESET,
                new byte[] {0, 0, 0, 0},
                null
            );
#endif
        }

        public IPEndPoint LocalEndPoint => (IPEndPoint)Socket.LocalEndPoint!;

        public void Start()
        {
            if (_started)
            {
                return;
            }

            _started = true;
            _backgroundWorkerTask = Task.Factory.StartNew(BackgroundWorker, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        protected void SignalStop()
        {
            _socketTaskCts.Cancel();

            // if never started, then also cleanup the socket, since the background worker will not do that
            if (!_started)
            {
                Dispose();
            }
        }

        protected void WaitUntilStop()
        {
            _backgroundWorkerTask?.Wait();
        }

        protected abstract void OnDatagramReceived(in DatagramInfo datagram);

        private void DoReceive(byte[] datagram, int length, EndPoint sender)
        {
            // process only datagrams big enough to contain valid QUIC packets
            if (datagram.Length < QuicConstants.MinimumPacketSize)
            {
                return;
            }

            OnDatagramReceived(new DatagramInfo(datagram, length, sender));
        }

        /// <summary>
        ///     Called when a connections <see cref="ManagedQuicConnection.ConnectionState"/> changes.
        /// </summary>
        /// <param name="connection">The connection.</param>
        /// <param name="newState">The new state of the connection.</param>
        /// <returns>True if the processing of the connection should be stopped.</returns>
        protected internal abstract bool
            OnConnectionStateChanged(ManagedQuicConnection connection, QuicConnectionState newState);

        private int ReceiveFrom(byte[] buffer, out EndPoint sender)
        {
            if (_remoteEndPoint != null)
            {
                // use method without explicit address because we use connected socket

                sender = _remoteEndPoint!;
                return Socket.Receive(buffer);
                // return Socket.ReceiveFrom(buffer, SocketFlags.None, ref sender);
            }
            else
            {
                sender = _localEndPoint!;
                return Socket.ReceiveFrom(buffer, ref sender);
            }
        }

        protected void SendTo(byte[] buffer, int size, EndPoint receiver)
        {
            if (_remoteEndPoint != null)
            {
                // Debug.Assert(Equals(receiver, _remoteEndPoint));
                Socket.Send(buffer.AsSpan(0, size), SocketFlags.None);
                // Socket.SendTo(buffer, 0, size, SocketFlags.None, _remoteEndPoint);
            }
            else
            {
                Socket.SendTo(buffer, 0, size, SocketFlags.None, receiver);
            }
        }

        protected class ReceiveOperationAsyncSocketArgs : SocketAsyncEventArgs
        {
            public ResettableCompletionSource<SocketReceiveFromResult> CompletionSource { get; } =
                new ResettableCompletionSource<SocketReceiveFromResult>();

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

        protected ReceiveOperationAsyncSocketArgs SocketReceiveEventArgs { get; } =
            new ReceiveOperationAsyncSocketArgs();

        internal ArrayPool<byte> ArrayPool { get; } = ArrayPool<byte>.Shared;

        private bool ReceiveFromAsync(ReceiveOperationAsyncSocketArgs args)
        {
            if (_remoteEndPoint != null)
            {
                // we are using connected sockets -> use Receive(...). We also have to set the expected
                // receiver address so that the receiving code later uses it

                // Debug.Assert(Socket.Connected);
                args.RemoteEndPoint = _remoteEndPoint!;
                return Socket.ReceiveAsync(args);
                // return Socket.ReceiveFromAsync(args);
            }

            Debug.Assert(_isServer);
            Debug.Assert(_localEndPoint != null);

            args.RemoteEndPoint = _localEndPoint!;
            return Socket.ReceiveFromAsync(args);
        }

        private ValueTask<SocketReceiveFromResult> ReceiveFromAsync(byte[] buffer, EndPoint sender,
            CancellationToken token)
        {
            SocketReceiveEventArgs.SetBuffer(buffer);

            // TODO-RZ: utilize cancellation token
            if (ReceiveFromAsync(SocketReceiveEventArgs))
            {
                return SocketReceiveEventArgs.CompletionSource.GetValueTask();
            }

            // operation completed synchronously
            return new ValueTask<SocketReceiveFromResult>(
                new SocketReceiveFromResult
                {
                    ReceivedBytes = SocketReceiveEventArgs.BytesTransferred,
                    RemoteEndPoint = SocketReceiveEventArgs.RemoteEndPoint!
                });
        }

        private async Task BackgroundWorker()
        {
            var token = _socketTaskCts.Token;

            try
            {
                while (!token.IsCancellationRequested)
                {
                    var buffer = ArrayPool.Rent(QuicConstants.MaximumAllowedDatagramSize);
                    var recv = await ReceiveFromAsync(buffer, _localEndPoint!, token);
                    DoReceive(buffer, recv.ReceivedBytes, recv.RemoteEndPoint);
                }
            }
            catch (OperationCanceledException)
            {
                // do nothing the socket context is closing
            }
            catch (Exception e)
            {
                if (NetEventSource.IsEnabled) NetEventSource.Error(this, e);
                OnException(e);
            }

            // cleanup everything
            Dispose();
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

        private void Dispose()
        {
            Socket.Dispose();
        }

        internal Task SendDatagram(in DatagramInfo datagram)
        {
            SendTo(datagram.Buffer, datagram.Length, datagram.RemoteEndpoint);
            return Task.CompletedTask;
        }
    }
}
