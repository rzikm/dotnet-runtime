using System.Diagnostics;
using System.IO;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed
{
    internal class ManagedQuicListener : QuicListenerProvider
    {
        private bool _disposed;

        private readonly Channel<ManagedQuicConnection> _acceptQueue;

        private IPEndPoint _listenEp;
        private readonly QuicListenerOptions _listenerOptions;
        private Socket? _socket;

        private bool _active;

        private readonly SocketAsyncEventArgs _socketAsyncEvent = new SocketAsyncEventArgs();

        private readonly QuicReader _reader;
        private readonly byte[] _recvBuffer = new byte[QuicConstants.MaximumAllowedDatagramSize];
        private readonly QuicSocketContext.RecvContext _recvContext = new QuicSocketContext.RecvContext(new ObjectPool<SentPacket>(10));

        public ManagedQuicListener(QuicListenerOptions options)
        {
            if (options.ServerAuthenticationOptions?.ServerCertificate == null)
            {
                if (!File.Exists(options.CertificateFilePath))
                    throw new FileNotFoundException("Certificate file not found", options.CertificateFilePath);
                if (!File.Exists(options.PrivateKeyFilePath))
                    throw new FileNotFoundException("Private key file not found", options.PrivateKeyFilePath);
            }

            _reader = new QuicReader(_recvBuffer);

            _listenerOptions = options;
            _listenEp = options.ListenEndPoint ?? throw new ArgumentNullException(nameof(options.ListenEndPoint));

            // TODO-RZ: explicitly reject incoming connections that do not fit the backlog
            _acceptQueue = Channel.CreateBounded<ManagedQuicConnection>(new BoundedChannelOptions(options.ListenBacklog)
            {
                SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.DropWrite
            });

            _socket = new Socket(_listenEp.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            _socketAsyncEvent.SetBuffer(_recvBuffer);
            _socketAsyncEvent.Completed += (sender, args) => OnReceiveAsyncFinished(args, false);
        }

        internal override IPEndPoint ListenEndPoint
        {
            get
            {
                ThrowIfDisposed();
                return _active ? (IPEndPoint)_socket.LocalEndPoint! : _listenEp;
            }
        }

        internal override async ValueTask<QuicConnectionProvider> AcceptConnectionAsync(
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            // TODO-RZ: make this non-async when the cast is no longer needed
            return await _acceptQueue.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }

        private void OnReceiveAsyncFinished(SocketAsyncEventArgs args, bool skipFirst)
        {
            bool finished;
            do
            {
                if (!skipFirst)
                {
                    var datagram = args.MemoryBuffer.Slice(0, args.BytesTransferred);
                    var sender = (IPEndPoint)args.RemoteEndPoint!;

                    OnDatagramReceived(datagram, sender);
                }

                // if next operation is pending or socket has been closed, then return
                args.RemoteEndPoint = _listenEp;
                finished = _socket?.ReceiveFromAsync(args) ?? true;
            } while (!finished);
        }

        private void OnDatagramReceived(Memory<byte> datagram, IPEndPoint sender)
        {
            if (datagram.Length < QuicConstants.MinimumPacketSize ||
                HeaderHelpers.GetPacketType(datagram.Span[0]) != PacketType.Initial)
            {
                // drop the packet
                return;
            }

            // new connection attempt
            var connection = new ManagedQuicConnection(_listenerOptions, sender);

            // transfer the connection its own context
            var endpoint = new IPEndPoint(sender.Address, _listenEp.Port);
            var newContext = new SingleConnectionSocketContext(endpoint, sender, connection, _acceptQueue.Writer);
            connection.SetSocketContext(newContext);

            _reader.Reset(datagram);
            _recvContext.Timestamp = Timestamp.Now;
            connection.ReceiveData(_reader, sender, _recvContext);

            // receive also all queued datagrams for this sender
            // sadly, we have to use exception based dispatch, because there is no way to find out that this was the
            // last datagram from given endpoint
            try
            {
                while (_socket!.Available > 0)
                {
                    EndPoint ep = connection.UnsafeRemoteEndPoint;
                    int length = _socket.ReceiveFrom(_recvBuffer, ref ep);
                    Debug.Assert(ep.Equals(connection.UnsafeRemoteEndPoint));

                    _reader.Reset(_recvBuffer.AsMemory(0, length));
                    connection.ReceiveData(_reader, sender, _recvContext);
                }
            }
            catch (SocketException)
            {
                // "service temporarily unavailable", we are done, no more datagrams for this connection
            }

            newContext.Ping();
            newContext.Start();
        }

        internal override void Start()
        {
            ThrowIfDisposed();

            // already listening
            if (_active)
            {
                return;
            }

            _active = true;

            _socket!.Blocking = false;
            _socket.Bind(_listenEp);
            // update the endpoint after the port is assigned
            _listenEp= (IPEndPoint)_socket.LocalEndPoint!;

            // kick off first async receive
            OnReceiveAsyncFinished(_socketAsyncEvent, true);
        }

        internal override void Close()
        {
            Dispose();
        }

        public override void Dispose()
        {
            if (_disposed) return;

            var s = _socket;
            _socket = null;
            _socket?.Dispose();

            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ManagedQuicListener));
            }
        }
    }
}
