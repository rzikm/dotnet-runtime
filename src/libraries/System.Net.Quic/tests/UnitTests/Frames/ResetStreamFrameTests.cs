// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Threading.Tasks;
using System.Net.Quic.Implementations.Managed;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Frames;
using System.Net.Quic.Implementations.Managed.Internal.Streams;
using Xunit;
using Xunit.Abstractions;
using ResetStreamFrame = System.Net.Quic.Tests.Harness.ResetStreamFrame;

namespace System.Net.Quic.Tests.Frames
{
    public class ResetStreamFrameTests : ManualTransmissionQuicTestBase
    {
        public ResetStreamFrameTests(ITestOutputHelper output) : base(output)
        {
            EstablishConnection();
        }

        [Fact]
        public async Task CausesReadStreamOperationsToThrow()
        {
            var stream = await Client.OpenStream(false);
            long errorCode = 15;

            Server.Ping();
            Intercept1Rtt(Server, Client, packet =>
            {
                packet.Frames.Add(new ResetStreamFrame()
                {
                    FinalSize = 0,
                    StreamId = stream.Id,
                    ApplicationErrorCode = errorCode
                });
            });

            var exception = AssertThrowsQuicException(QuicError.StreamAborted, () => stream.Read(Span<byte>.Empty));
            Assert.Equal(errorCode, exception.ApplicationErrorCode);
        }

        private void CloseConnectionCommon(ResetStreamFrame frame, TransportErrorCode errorCode, string reason)
        {
            Server.Ping();
            Intercept1Rtt(Server, Client, packet => { packet.Frames.Add(frame); });

            Send1Rtt(Client, Server).ShouldHaveConnectionClose(
                errorCode,
                reason,
                FrameType.ResetStream);
        }

        [Fact]
        public void ClosesConnection_WhenReceivedForNonReadableStream()
        {
            CloseConnectionCommon(new ResetStreamFrame()
                {
                    StreamId = StreamHelpers.ComposeStreamId(StreamType.ClientInitiatedUnidirectional, 0),
                    ApplicationErrorCode = 14
                },
                TransportErrorCode.StreamStateError, QuicTransportError.StreamNotReadable);
        }

        [Fact]
        public void ClosesConnection_WhenViolatingStreamLimit()
        {
            CloseConnectionCommon(new ResetStreamFrame()
                {
                    // TODO: value of streamId based on listener options
                    StreamId = StreamHelpers.ComposeStreamId(StreamType.ServerInitiatedUnidirectional, int.MaxValue),
                    ApplicationErrorCode = 14
                },
                TransportErrorCode.StreamLimitError, QuicTransportError.StreamsLimitViolated);
        }

        [Fact]
        public async Task RetransmittedAfterLoss()
        {
            var stream = await Client.OpenStream(false);
            long errorCode = 15;
            stream.AbortWrite(errorCode);

            Lose1RttWithFrameAndCheckIfItIsResentLater<ResetStreamFrame>(Client, Server);
        }
    }
}
