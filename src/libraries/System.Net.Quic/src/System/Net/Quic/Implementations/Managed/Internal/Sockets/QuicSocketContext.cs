// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System.Buffers;
using System.Diagnostics;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Headers;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed.Internal.Sockets
{
    /// <summary>
    ///     Class responsible for serving a socket for QUIC connections.
    /// </summary>
    internal abstract class QuicSocketContext
    {
        private readonly EndPoint? _localEndPoint;
        private readonly EndPoint? _remoteEndPoint;
        private readonly bool _isServer;
        private readonly CancellationTokenSource _socketTaskCts;

        private bool _started;

        private readonly Socket _socket;

        protected QuicSocketContext(EndPoint? localEndPoint, EndPoint? remoteEndPoint, bool isServer)
        {
            _socket = new Socket((localEndPoint ?? remoteEndPoint)!.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            _localEndPoint = localEndPoint;
            _remoteEndPoint = remoteEndPoint;

            _isServer = isServer;

            _socketTaskCts = new CancellationTokenSource();

            SetupSocket(localEndPoint, remoteEndPoint);
        }

        private void SetupSocket(EndPoint? localEndPoint, EndPoint? remoteEndPoint)
        {
            if (_socket.AddressFamily == AddressFamily.InterNetwork)
            {
                _socket.DontFragment = true;
            }

            if (localEndPoint != null)
            {
                _socket.Bind(localEndPoint);
            }

            if (remoteEndPoint != null)
            {
                _socket.Connect(remoteEndPoint);
            }

#if WINDOWS
            // disable exception when client forcibly closes the socket.
            // https://stackoverflow.com/questions/38191968/c-sharp-udp-an-existing-connection-was-forcibly-closed-by-the-remote-host

            const int SIO_UDP_CONNRESET = -1744830452;
            _socket.IOControl(
                (IOControlCode)SIO_UDP_CONNRESET,
                new byte[] {0, 0, 0, 0},
                null
            );
#endif
        }

        public IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint!;

        public void Start()
        {
            if (_started)
            {
                return;
            }

            _started = true;

            _ = Task.Run(async () => {
                while (!_socketTaskCts.IsCancellationRequested)
                {
                    // use fresh buffer for each receive, since the previous one is still being processed
                    var buffer = ArrayPool.Rent(1200);

                    DatagramInfo datagram;

                    if (_remoteEndPoint != null)
                    {
                        var read = await _socket.ReceiveAsync(buffer).ConfigureAwait(false);
                        datagram = new DatagramInfo(buffer, read, _remoteEndPoint);
                    }
                    else
                    {
                        var res = await _socket.ReceiveFromAsync(buffer, _localEndPoint!).ConfigureAwait(false);
                        datagram = new DatagramInfo(buffer, res.ReceivedBytes, res.RemoteEndPoint);
                    }

                    // process only datagrams big enough to contain valid QUIC packets
                    if (datagram.Length >= QuicConstants.MinimumPacketSize)
                    {
                        OnDatagramReceived(datagram);
                    }
                }
            });
        }

        internal ArrayPool<byte> ArrayPool { get; } = ArrayPool<byte>.Shared;

        protected void SignalStop()
        {
            _socketTaskCts.Cancel();
            Dispose();
        }

        protected abstract void OnDatagramReceived(in DatagramInfo datagram);

        /// <summary>
        ///     Called when a connections <see cref="ManagedQuicConnection.ConnectionState"/> changes.
        /// </summary>
        /// <param name="connection">The connection.</param>
        /// <param name="newState">The new state of the connection.</param>
        /// <returns>True if the processing of the connection should be stopped.</returns>
        protected internal abstract bool
            OnConnectionStateChanged(ManagedQuicConnection connection, QuicConnectionState newState);

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
            _socket.Dispose();
        }

        internal void SendDatagram(in DatagramInfo datagram)
        {
            if (_remoteEndPoint != null)
            {
                _socket.Send(datagram.Buffer.AsSpan(0, datagram.Length), SocketFlags.None);
            }
            else
            {
                _socket.SendTo(datagram.Buffer, 0, datagram.Length, SocketFlags.None, datagram.RemoteEndpoint);
            }
        }
    }
}
