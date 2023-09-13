// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Frames;
using System.Net.Quic.Tests.Harness;
using System.Threading.Tasks;
using Xunit;
using ConnectionCloseFrame = System.Net.Quic.Tests.Harness.ConnectionCloseFrame;

namespace System.Net.Quic.Tests
{
    internal static class TestHelpers
    {
        public static TFrame ShouldHaveFrame<TFrame>(this IFramePacket packet) where TFrame : FrameBase
        {
            var frame = packet.Frames.OfType<TFrame>().SingleOrDefault();
            Assert.True(frame != null, $"Packet does not contain {typeof(TFrame).Name}s.");
            return frame!;
        }

        public static void ShouldNotHaveFrame<TFrame>(this IFramePacket packet) where TFrame : FrameBase
        {
            var frame = packet.Frames.OfType<TFrame>().SingleOrDefault();
            Assert.True(frame == null, $"Packet does contain {typeof(TFrame).Name}, but was expected not to.");
        }

        public static void ShouldHaveConnectionClose(this IFramePacket packet, TransportErrorCode error,
            string? reason = null, FrameType frameType = FrameType.Padding)
        {
            var frame = packet.ShouldHaveFrame<ConnectionCloseFrame>();

            Assert.Equal(error, frame.ErrorCode);
            // if (reason != null)
                Assert.Equal(reason, frame.ReasonPhrase);
            // if (frameType != FrameType.Padding)
                Assert.Equal(frameType, frame.ErrorFrameType);
        }

    }

    internal static class AssertHelpers
    {
        internal static async Task<QuicException> ThrowsQuicExceptionAsync(QuicError expectedError, Func<Task> action)
        {
            var ex = await Assert.ThrowsAsync<QuicException>(action);
            Assert.Equal(expectedError, ex.QuicError);
            return ex;
        }

        internal static QuicException ThrowsQuicException(QuicError expectedError, Action action)
        {
            var ex = Assert.Throws<QuicException>(action);
            Assert.Equal(expectedError, ex.QuicError);
            return ex;
        }
    }
}
