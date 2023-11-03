// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Streams;
using System.Threading;
using System.Threading.Channels;

namespace System.Net.Quic.Implementations.Managed
{
    /// <summary>
    ///     Collection of Quic streams.
    /// </summary>
    internal sealed class StreamCollection
    {
        /// <summary>
        ///     All opened streams by their id;
        /// </summary>
        private ConcurrentDictionary<long, ManagedQuicStream> _streams = new ConcurrentDictionary<long, ManagedQuicStream>();

        /// <summary>
        ///     Number of total streams by their type.
        /// </summary>
        private readonly int[] _streamCounts = new int[4];

        /// <summary>
        ///     All streams which are flushable (have data to send).
        /// </summary>
        private readonly LinkedList<ManagedQuicStream> _flushable = new LinkedList<ManagedQuicStream>();

        /// <summary>
        ///     All streams which require updating flow control bounds.
        /// </summary>
        private readonly LinkedList<ManagedQuicStream> _updateQueue = new LinkedList<ManagedQuicStream>();

        /// <summary>
        ///     Channel of streams that were opened by the peer but not yet accepted by this endpoint.
        /// </summary>
        internal Channel<ManagedQuicStream> IncomingStreams { get; } =
            Channel.CreateUnbounded<ManagedQuicStream>(new UnboundedChannelOptions()
            {
                SingleReader = false,
                SingleWriter = true
            });

        /// <summary>
        ///     Returns all streams that are currently open.
        /// </summary>
        internal IEnumerable<ManagedQuicStream> OpenStreams => _streams.Values;

        /// <summary>
        ///     Returns the stream with given ID or null if the stream hasn't been created yet.
        /// </summary>
        /// <param name="streamId">The Id of the stream</param>
        internal ManagedQuicStream? TryGetStream(long streamId) => _streams.GetValueOrDefault(streamId);

        /// <summary>
        ///     Returns true if the stream collection has streams to be flushed.
        /// </summary>
        internal bool HasFlushableStreams
        {
            get
            {
                // if it is false, then it surely is not-null
                while (_flushable.First?.Value.SendStream?.IsFlushable == false)
                {
                    GetFirstFlushableStream();
                }

                return _flushable.First != null;
            }
        }

        /// <summary>
        ///     Removes first flushable stream from the queue and returns it. Returns null if no
        ///     flushable stream is available.
        /// </summary>
        internal ManagedQuicStream? GetFirstFlushableStream()
        {
            if (_flushable.First != null)
            {
                lock (_flushable)
                {
                    var first = _flushable.First;

                    _flushable.RemoveFirst();
                    return first.Value;
                }
            }

            return null;
        }

        /// <summary>
        ///     Returns true if there are streams awaiting an update.
        /// </summary>
        internal bool HasUpdateableStreams => _updateQueue.First != null;

        /// <summary>
        ///     Removes first stream from the update queue and returns it. Returns null if no such
        ///     stream is available.
        /// </summary>
        internal ManagedQuicStream? GetFirstStreamForUpdate()
        {
            lock (_updateQueue)
            {
                var first = _updateQueue.First;
                if (first == null)
                {
                    return null;
                }

                _updateQueue.RemoveFirst();
                return first.Value;
            }
        }

        internal ManagedQuicStream CreateOutboundStream(bool unidirectional, ManagedQuicConnection connection)
        {
            var type = StreamHelpers.GetLocallyInitiatedType(connection.IsServer, unidirectional);

            lock (_streamCounts)
            {
                var index = Interlocked.Increment(ref _streamCounts[(int)type]) - 1;
                // check limits
                var limit = unidirectional
                    ? connection._sendLimits.MaxStreamsUni
                    : connection._sendLimits.MaxStreamsBidi;


                long nextId = StreamHelpers.ComposeStreamId(type, index);

                var stream = CreateStream(nextId, true, connection);

                bool success = _streams.TryAdd(nextId, stream);
                Debug.Assert(success, "Failed to add stream");

                if (index < limit)
                {
                    // System.Console.WriteLine($"Starting stream with index from Create: {streamCount}");
                    stream.NotifyStarted();
                }
                else
                {
                    // System.Console.WriteLine($"Blocking stream with index from Create: {streamCount}");
                }

                return stream;
            }
        }

        internal bool TryGetOrCreateStream(long streamId, bool createIfMissing, ManagedQuicConnection connection, out ManagedQuicStream? stream)
        {
            // hot path
            if (_streams.TryGetValue(streamId, out stream))
            {
                return true;
            }

            // if not found, check limits
            var type = StreamHelpers.GetStreamType(streamId);
            long index = StreamHelpers.GetStreamIndex(streamId);
            ref int streamCount = ref _streamCounts[(int)type];

            // we can read here under the lock because the stream count only
            // ever increases and we read it again after acquiring the lock
            if (index < streamCount)
            {
                // the stream has already been released, return null
                return true;
            }

            if (!createIfMissing)
            {
                // not yet created, likely stream limit violation
                return false;
            }

            Debug.Assert(!StreamHelpers.IsLocallyInitiated(connection.IsServer, streamId), "Peer asking for locally initiated stream without us creating it first");

            {
                // asking for new stream, check limits first
                var limit = StreamHelpers.IsBidirectional(streamId)
                    ? connection._receiveLimits.MaxStreamsBidi
                    : connection._receiveLimits.MaxStreamsUni;

                if (index >= limit)
                {
                    return false;
                }

                // create also all lower-numbered streams
                while (streamCount <= index)
                {
                    long nextId = StreamHelpers.ComposeStreamId(type, streamCount);

                    stream = CreateStream(nextId, false, connection);

                    bool success = _streams.TryAdd(nextId, stream);
                    Debug.Assert(success, "Failed to add stream");

                    success = IncomingStreams.Writer.TryWrite(stream);
                    // reserving space should be assured by connection stream limits
                    Debug.Assert(success, "Failed to write into IncomingStreams");

                    _streamCounts[(int)type]++;
                }
            }

            return true;
        }

        internal void OnStreamLimitUpdated(StreamType type, long maxCount, long prevCount)
        {
            lock (_streamCounts)
            {
                for (long index = prevCount; index < maxCount; index++)
                {
                    long id = StreamHelpers.ComposeStreamId(type, index);

                    if (!_streams.TryGetValue(id, out var stream))
                    {
                        // System.Console.WriteLine($"Stopping unblock loop at index {index}");
                        break;
                    }

                    // System.Console.WriteLine($"Starting stream with index from OnLimitUpdated: {index}");
                    stream.NotifyStarted();
                }
            }
        }

        private static ManagedQuicStream CreateStream(long streamId, bool isLocal, ManagedQuicConnection connection)
        {
            bool unidirectional = !StreamHelpers.IsBidirectional(streamId);

            // use initial flow control limits
            (long? maxDataInbound, long? maxDataOutbound) = (isLocal, unidirectional) switch
            {
                // local unidirectional
                (true, true) => ((long?)null, (long?)connection._peerTransportParameters.InitialMaxStreamDataUni),
                // local bidirectional
                (true, false) => ((long?)connection._localTransportParameters.InitialMaxStreamDataBidiLocal, (long?)connection._peerTransportParameters.InitialMaxStreamDataBidiRemote),
                // remote unidirectional
                (false, true) => ((long?)connection._localTransportParameters.InitialMaxStreamDataUni, (long?)null),
                // remote bidirectional
                (false, false) => ((long?)connection._localTransportParameters.InitialMaxStreamDataBidiRemote, (long?)connection._peerTransportParameters.InitialMaxStreamDataBidiLocal),
            };

            ReceiveStream? recvStream = maxDataInbound != null
                ? new ReceiveStream(maxDataInbound.Value)
                : null;

            SendStream? sendStream = maxDataOutbound != null
                ? new SendStream(maxDataOutbound.Value)
                : null;

            return new ManagedQuicStream(streamId, recvStream, sendStream, connection);
        }

        internal bool MarkFlushable(ManagedQuicStream stream)
        {
            Debug.Assert(stream.CanWrite);

            return AddToListSynchronized(_flushable, stream._flushableListNode);
        }

        internal bool MarkForUpdate(ManagedQuicStream stream)
        {
            return AddToListSynchronized(_updateQueue, stream._updateQueueListNode);
        }

        private static bool AddToListSynchronized(LinkedList<ManagedQuicStream> list, LinkedListNode<ManagedQuicStream> node)
        {
            // use double checking to prevent frequent locking
            if (node.List == null)
            {
                lock (list)
                {
                    if (node.List == null)
                    {
                        list.AddLast(node);
                        return true;
                    }
                }
            }

            return false;
        }

        private static void RemoveFromListSynchronized(LinkedList<ManagedQuicStream> list, LinkedListNode<ManagedQuicStream> node)
        {
            // use double checking to prevent frequent locking
            if (node.List != null)
            {
                lock (list)
                {
                    if (node.List != null)
                    {
                        list.Remove(node);
                    }
                }
            }
        }

        internal void Remove(ManagedQuicStream stream)
        {
            RemoveFromListSynchronized(_flushable, stream._flushableListNode);
            RemoveFromListSynchronized(_updateQueue, stream._updateQueueListNode);

            _streams.TryRemove(stream.Id, out _);
        }
    }
}
