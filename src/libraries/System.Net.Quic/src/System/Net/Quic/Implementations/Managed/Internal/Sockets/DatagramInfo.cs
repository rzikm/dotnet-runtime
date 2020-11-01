namespace System.Net.Quic.Implementations.Managed.Internal.Sockets
{
    internal readonly struct DatagramInfo
    {
        public DatagramInfo(byte[] buffer, int length, EndPoint remoteEndpoint)
        {
            Buffer = buffer;
            Length = length;
            RemoteEndpoint = remoteEndpoint;
        }

        public byte[] Buffer { get; }
        public int Length { get; }
        public EndPoint RemoteEndpoint { get; }
    }
}
