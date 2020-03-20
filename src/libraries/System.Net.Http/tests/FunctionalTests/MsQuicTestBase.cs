namespace System.Net.Quic.Tests
{
    public class MsQuicTestBase : QuicTestBase
    {
        internal MsQuicTestBase() : base(QuicImplementationProviders.Managed)
        {
        }
    }
}
