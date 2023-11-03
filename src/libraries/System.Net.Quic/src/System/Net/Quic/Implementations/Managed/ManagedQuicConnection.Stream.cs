// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Collections.Concurrent;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Frames;
using System.Net.Quic.Implementations.Managed.Internal.Streams;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed
{
    public partial class ManagedQuicConnection
    {
        internal struct ConnectionFlowControlLimits
        {
            private long _maxData;

            /// <summary>
            ///     Maximum amount of data the endpoint is allowed to send.
            /// </summary>
            internal long MaxData => _maxData;

            internal void UpdateMaxData(long value)
            {
                _maxData = Math.Max(_maxData, value);
            }

            internal void AddMaxData(long value)
            {
                Interlocked.Add(ref _maxData, value);
            }

            /// <summary>
            ///     Maximum number of bidirectional streams the endpoint is allowed to open.
            /// </summary>
            internal long MaxStreamsBidi { get; private set; }

            internal void UpdateMaxStreamsBidi(long value)
            {
                MaxStreamsBidi = Math.Max(MaxStreamsBidi, value);
            }

            /// <summary>
            ///     Maximum number of unidirectional streams the endpoint is allowed to open.
            /// </summary>
            internal long MaxStreamsUni { get; private set; }

            internal void UpdateMaxStreamsUni(long value)
            {
                MaxStreamsUni = Math.Max(MaxStreamsUni, value);
            }
        }

        /// <summary>
        ///     True if packet with <see cref="MaxDataFrame"/> is waiting for acknowledgement.
        /// </summary>
        private bool MaxDataFrameSent { get; set; }

        /// <summary>
        ///     The highest StreamId sent in <see cref="MaxStreamsFrame"/> for unidirectional streams there.
        /// </summary>
        private long MaxStreamsUniFrameSent { get; set; }

        /// <summary>
        ///     The highest StreamId sent in <see cref="MaxStreamsFrame"/> for bidirectional streams there.
        /// </summary>
        private long MaxStreamsBidiFrameSent { get; set; }

        /// <summary>
        ///     Sum of maximum offsets of data sent across all streams.
        /// </summary>
        private long SentData { get; set; }

        /// <summary>
        ///     Sum of maximum offsets of data received across all streams.
        /// </summary>
        private long ReceivedData { get; set; }

        /// <summary>
        ///     Opens a new outbound stream with lowest available stream id.
        /// </summary>
        /// <param name="unidirectional">True if the stream should be unidirectional.</param>
        /// <param name="cancellationToken">Cancellation token for this operation.</param>
        /// <returns></returns>
        internal ValueTask<ManagedQuicStream> OpenStream(bool unidirectional, CancellationToken cancellationToken = default)
        {
            var stream = _streams.CreateOutboundStream(unidirectional, this);

            if (stream.IsStarted)
            {
                return new ValueTask<ManagedQuicStream>(stream);
            }

            // wait until peer increases the stream limits
            return WaitForStreamStart(stream, cancellationToken);

            static async ValueTask<ManagedQuicStream> WaitForStreamStart(ManagedQuicStream stream, CancellationToken cancellationToken)
            {
                await stream.WaitForStartAsync(cancellationToken).ConfigureAwait(false);
                return stream;
            }
        }

        /// <summary>
        ///     Gets a stream with given id. Use in cases where you are sure the stream exists.
        /// </summary>
        /// <param name="streamId">Id of the stream.</param>
        /// <returns>The stream associated with provided id.</returns>
        private ManagedQuicStream? GetStream(long streamId)
        {
            return _streams.TryGetStream(streamId);
        }

        /// <summary>
        ///     Tries to get the stream with given id. Creates also all streams of the same type with lower id. Returns
        ///     false if creating the remote initiated stream would violate stream limits imposed by this endpoint.
        /// </summary>
        /// <param name="streamId">Id of the stream to get or create.</param>
        /// <param name="stream">The stream, can be null if already released or outside of stream limits.</param>
        /// <returns>True if the stream limit was not validated, false otherwise.</returns>
        private bool TryGetOrCreateStream(long streamId, out ManagedQuicStream? stream)
        {
            return _streams.TryGetOrCreateStream(streamId, !StreamHelpers.IsLocallyInitiated(IsServer, streamId), this, out stream);
        }

        internal ManagedQuicStream? AcceptStream()
        {
            _streams.IncomingStreams.Reader.TryRead(out var stream);
            return stream;
        }

        internal void OnStreamDataWritten(ManagedQuicStream stream)
        {
            // We can't check IsFlushable because we are running on user thread and
            // we are racing with socket thread on internal structures.
            if (stream.SendStream!.UnsentOffset < stream.SendStream.MaxData || stream.SendStream.SizeKnown)
            {
                // no need to ping if the thread is already spinning
                var doPing = _streams.MarkFlushable(stream);

                if (doPing)
                {
                    _socketContext!.WakeUp();
                }
            }
        }

        internal void OnStreamDataRead(ManagedQuicStream stream, int bytesRead)
        {
            _receiveLimits.AddMaxData(bytesRead);
            if (stream.ReceiveStream!.ShouldUpdateMaxData() || stream.ReceiveStream.CanReleaseFlowControl)
            {
                OnStreamStateUpdated(stream);
            }
        }

        internal void OnStreamStateUpdated(ManagedQuicStream stream)
        {
            _streams.MarkForUpdate(stream);
            _socketContext!.WakeUp();
        }

        internal void ReleaseStream(ManagedQuicStream stream)
        {
            if (!StreamHelpers.IsLocallyInitiated(IsServer, stream.Id) && !stream.FlowControlReleased)
            {
                // remote initiated stream closed, increase streams limit.
                if (StreamHelpers.IsBidirectional(stream.Id))
                {
                    // System.Console.WriteLine($"Updated local limits: {_receiveLimits.MaxStreamsBidi + 1}");
                    _receiveLimits.UpdateMaxStreamsBidi(_receiveLimits.MaxStreamsBidi + 1);
                }
                else
                {
                    _receiveLimits.UpdateMaxStreamsUni(_receiveLimits.MaxStreamsUni + 1);
                }

                stream.FlowControlReleased = true;
            }
            // System.Console.WriteLine($"Releasing stream {stream.Id}");
            _streams.Remove(stream);
        }
    }
}
