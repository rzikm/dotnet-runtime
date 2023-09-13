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
using StopSendingFrame = System.Net.Quic.Tests.Harness.StopSendingFrame;

namespace System.Net.Quic.Tests.Frames
{
    public class StopSendingFrameTests : ManualTransmissionQuicTestBase
    {
        public StopSendingFrameTests(ITestOutputHelper output) : base(output)
        {
            EstablishConnection();
        }

        [Fact]
        public async Task ElicitsResetStream()
        {
            var stream = await Client.OpenStream(false);
            long errorCode = 15;
            stream.AbortRead(errorCode);

            Send1RttWithFrame<StopSendingFrame>(Client, Server);

            var frame = Send1RttWithFrame<ResetStreamFrame>(Server, Client);

            Assert.Equal(stream.Id, frame.StreamId);
            Assert.Equal(errorCode, frame.ApplicationErrorCode);
            Assert.Equal(0, frame.FinalSize);
        }

        private void CloseConnectionCommon(StopSendingFrame frame, TransportErrorCode errorCode, string reason)
        {
            Client.Ping();
            Intercept1Rtt(Client, Server, packet => { packet.Frames.Add(frame); });

            Send1Rtt(Server, Client).ShouldHaveConnectionClose(
                errorCode,
                reason,
                FrameType.StopSending);
        }

        [Fact]
        public async Task ClosesConnection_WhenReceivedForNonWritableStream()
        {
            var stream = await Client.OpenStream(true);

            CloseConnectionCommon(new StopSendingFrame()
                {
                    StreamId = stream.Id,
                    ApplicationErrorCode = 14
                },
                TransportErrorCode.StreamStateError, QuicTransportError.StreamNotWritable);
        }

        [Fact]
        public void ClosesConnection_WhenReceivedForUncreatedLocallyInitiatedStream()
        {
            CloseConnectionCommon(
                new StopSendingFrame()
                {
                    StreamId = StreamHelpers.ComposeStreamId(StreamType.ServerInitiatedBidirectional, 0),
                    ApplicationErrorCode = 14
                },
                TransportErrorCode.StreamStateError, QuicTransportError.StreamNotCreated);
        }

        [Fact]
        public void ClosesConnection_WhenViolatingStreamLimit()
        {
            CloseConnectionCommon(
                new StopSendingFrame()
                {
                    // TODO: value of streamId based on listener options
                    StreamId = StreamHelpers.ComposeStreamId(StreamType.ClientInitiatedBidirectional, int.MaxValue),
                    ApplicationErrorCode = 14
                },
                TransportErrorCode.StreamLimitError, QuicTransportError.StreamsLimitViolated);
        }

        [Fact]
        public async Task RetransmittedAfterLoss()
        {
            var stream = await Client.OpenStream(false);
            long errorCode = 15;
            stream.AbortRead(errorCode);

            Lose1RttWithFrameAndCheckIfItIsResentLater<StopSendingFrame>(Client, Server);
        }
    }
}
