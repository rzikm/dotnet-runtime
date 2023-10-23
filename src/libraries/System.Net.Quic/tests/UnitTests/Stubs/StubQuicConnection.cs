namespace System.Net.Quic;

public partial class QuicConnection : System.IAsyncDisposable
{
    protected QuicConnection(bool managed) { }
    public static bool IsSupported { get { throw new Exception("Not overriden"); } }
    public virtual System.Net.IPEndPoint LocalEndPoint { get { throw new Exception("Not overriden"); } }
    public virtual System.Net.Security.SslApplicationProtocol NegotiatedApplicationProtocol { get { throw new Exception("Not overriden"); } }
    public virtual System.Security.Cryptography.X509Certificates.X509Certificate? RemoteCertificate { get { throw new Exception("Not overriden"); } }
    public virtual System.Net.IPEndPoint RemoteEndPoint { get { throw new Exception("Not overriden"); } }
    public virtual string TargetHostName { get { throw new Exception("Not overriden"); } }
    public virtual System.Threading.Tasks.ValueTask<System.Net.Quic.QuicStream> AcceptInboundStreamAsync(System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public virtual System.Threading.Tasks.ValueTask CloseAsync(long errorCode, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public static System.Threading.Tasks.ValueTask<System.Net.Quic.QuicConnection> ConnectAsync(System.Net.Quic.QuicClientConnectionOptions options, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public virtual System.Threading.Tasks.ValueTask DisposeAsync() { throw new Exception("Not overriden"); }
    public virtual System.Threading.Tasks.ValueTask<System.Net.Quic.QuicStream> OpenOutboundStreamAsync(System.Net.Quic.QuicStreamType type, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public override string ToString() { throw new Exception("Not overriden"); }
}

public partial class QuicListener : System.IAsyncDisposable
{
    protected QuicListener(bool managed) { }
    public static bool IsSupported { get { throw new Exception("Not overriden"); } }
    public virtual System.Net.IPEndPoint LocalEndPoint { get { throw new Exception("Not overriden"); } }
    public virtual System.Threading.Tasks.ValueTask<System.Net.Quic.QuicConnection> AcceptConnectionAsync(System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public virtual System.Threading.Tasks.ValueTask DisposeAsync() { throw new Exception("Not overriden"); }
    public static System.Threading.Tasks.ValueTask<System.Net.Quic.QuicListener> ListenAsync(System.Net.Quic.QuicListenerOptions options, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public override string ToString() { throw new Exception("Not overriden"); }
}


public partial class QuicStream : System.IO.Stream
{
    protected QuicStream(bool managed) { }
    public override bool CanRead { get { throw new Exception("Not overriden"); } }
    public override bool CanSeek { get { throw new Exception("Not overriden"); } }
    public override bool CanTimeout { get { throw new Exception("Not overriden"); } }
    public override bool CanWrite { get { throw new Exception("Not overriden"); } }
    public virtual long Id { get { throw new Exception("Not overriden"); } }
    public override long Length { get { throw new Exception("Not overriden"); } }
    public override long Position { get { throw new Exception("Not overriden"); } set { } }
    public virtual System.Threading.Tasks.Task ReadsClosed { get { throw new Exception("Not overriden"); } }
    public override int ReadTimeout { get { throw new Exception("Not overriden"); } set { } }
    public virtual System.Net.Quic.QuicStreamType Type { get { throw new Exception("Not overriden"); } }
    public virtual System.Threading.Tasks.Task WritesClosed { get { throw new Exception("Not overriden"); } }
    public override int WriteTimeout { get { throw new Exception("Not overriden"); } set { } }
    public virtual void Abort(System.Net.Quic.QuicAbortDirection abortDirection, long errorCode) { }
    public override System.IAsyncResult BeginRead(byte[] buffer, int offset, int count, System.AsyncCallback? callback, object? state) { throw new Exception("Not overriden"); }
    public override System.IAsyncResult BeginWrite(byte[] buffer, int offset, int count, System.AsyncCallback? callback, object? state) { throw new Exception("Not overriden"); }
    public virtual void CompleteWrites() { }
    protected override void Dispose(bool disposing) { }
    public override System.Threading.Tasks.ValueTask DisposeAsync() { throw new Exception("Not overriden"); }
    public override int EndRead(System.IAsyncResult asyncResult) { throw new Exception("Not overriden"); }
    public override void EndWrite(System.IAsyncResult asyncResult) { }
    public override void Flush() { }
    public override System.Threading.Tasks.Task FlushAsync(System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public override int Read(byte[] buffer, int offset, int count) { throw new Exception("Not overriden"); }
    public override int Read(System.Span<byte> buffer) { throw new Exception("Not overriden"); }
    public override System.Threading.Tasks.Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public override System.Threading.Tasks.ValueTask<int> ReadAsync(System.Memory<byte> buffer, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public override int ReadByte() { throw new Exception("Not overriden"); }
    public override long Seek(long offset, System.IO.SeekOrigin origin) { throw new Exception("Not overriden"); }
    public override void SetLength(long value) { }
    public override string ToString() { throw new Exception("Not overriden"); }
    public override void Write(byte[] buffer, int offset, int count) { }
    public override void Write(System.ReadOnlySpan<byte> buffer) { }
    public override System.Threading.Tasks.Task WriteAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public virtual System.Threading.Tasks.ValueTask WriteAsync(System.ReadOnlyMemory<byte> buffer, bool completeWrites, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public override System.Threading.Tasks.ValueTask WriteAsync(System.ReadOnlyMemory<byte> buffer, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken)) { throw new Exception("Not overriden"); }
    public override void WriteByte(byte value) { }
}
