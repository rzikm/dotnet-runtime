// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System.Diagnostics;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Frames;
using System.Net.Quic.Implementations.Managed.Internal.Recovery;
using System.Net.Quic.Implementations.Managed.Internal.Sockets;
using System.Net.Quic.Implementations.Managed.Internal.Streams;

namespace System.Net.Quic.Implementations.Managed
{
    internal partial class ManagedQuicConnection
    {
        /// <summary>
        ///     Returns true if the frame type requires receiver to sent acknowledgement before the maximum ack delay.
        /// </summary>
        /// <param name="frameType">The frame type.</param>
        private static bool IsAckEliciting(FrameType frameType)
        {
            return frameType switch
            {
                FrameType.Padding => false,
                FrameType.Ack => false,
                FrameType.ConnectionCloseQuic => false,
                FrameType.ConnectionCloseApplication => false,
                // all other frame types are ack eliciting
                _ => true
            };
        }

        /// <summary>
        ///     Returns true if the QUIC protocol allows given frame type to be sent in the given packet type.
        /// </summary>
        /// <param name="frameType">The frame type.</param>
        /// <param name="packetType">The packet type.</param>
        private bool IsFrameAllowed(FrameType frameType, PacketType packetType)
        {
            return packetType switch
            {
                // 1-RTT packets may contain any frame, but HANDSHAKE_DONE may only be sent by server
                PacketType.OneRtt => frameType != FrameType.HandshakeDone || !IsServer,

                PacketType.Initial => frameType switch
                {
                    FrameType.Padding => true,
                    FrameType.Ping => true,
                    FrameType.Ack => true,
                    FrameType.AckWithEcn => true,
                    FrameType.Crypto => true,
                    FrameType.ConnectionCloseQuic => true,
                    _ => false
                },

                PacketType.ZeroRtt => frameType switch
                {
                    FrameType.Ack => false,
                    FrameType.AckWithEcn => false,
                    FrameType.Crypto => false,
                    FrameType.NewToken => false,
                    FrameType.ConnectionCloseQuic => false,
                    FrameType.ConnectionCloseApplication => false,
                    FrameType.HandshakeDone => false,
                    _ => true
                },

                PacketType.Handshake => frameType switch
                {
                    FrameType.Padding => true,
                    FrameType.Ping => true,
                    FrameType.Ack => true,
                    FrameType.AckWithEcn => true,
                    FrameType.Crypto => true,
                    FrameType.ConnectionCloseQuic => true,
                    _ => false
                },

                // these two types do not carry frames, and should never be passed to this function
                // PacketType.Retry,
                // PacketType.VersionNegotiation,
                _ => throw new ArgumentOutOfRangeException(nameof(packetType), packetType, null)
            };
        }

        /// <summary>
        ///     Processes the sequence of frames in the given reader.
        /// </summary>
        /// <param name="reader">Reader with the packet payload (frames).</param>
        /// <param name="packetType">The type of the packet in which the payload was sent.</param>
        /// <param name="context">Contextual data for the current receive operation.</param>
        private ProcessPacketResult ProcessFrames(QuicReader reader, PacketType packetType, QuicSocketContext.RecvContext context)
        {
            bool ackEliciting = false;

            while (reader.BytesLeft > 0)
            {
                var frameType = reader.PeekFrameType();

                if (!IsFrameAllowed(frameType, packetType))
                {
                    return CloseConnection(TransportErrorCode.ProtocolViolation, QuicError.FrameNotAllowed, frameType);
                }

                ackEliciting |= IsAckEliciting(frameType);

                ProcessPacketResult result = frameType switch
                {
                    FrameType.Padding => DiscardPadding(reader),
                    FrameType.Ping => ProcessPingFrame(reader),
                    FrameType.Ack => ProcessAckFrame(reader, packetType, context),
                    FrameType.AckWithEcn => ProcessAckFrame(reader, packetType, context),
                    FrameType.ResetStream => ProcessResetStreamFrame(reader),
                    FrameType.StopSending => ProcessStopSendingFrame(reader),
                    FrameType.Crypto => ProcessCryptoFrame(reader, packetType, context),
                    FrameType.NewToken => ProcessNewTokenFrame(reader),
                    FrameType.MaxData => ProcessMaxDataFrame(reader),
                    FrameType.MaxStreamData => ProcessMaxStreamDataFrame(reader),
                    FrameType.MaxStreamsBidirectional => ProcessMaxStreamsFrame(reader),
                    FrameType.MaxStreamsUnidirectional => ProcessMaxStreamsFrame(reader),
                    FrameType.DataBlocked => ProcessDataBlockedFrame(reader),
                    FrameType.StreamDataBlocked => ProcessStreamDataBlockedFrame(reader),
                    FrameType.StreamsBlockedBidirectional => ProcessStreamsBlockedFrame(reader),
                    FrameType.StreamsBlockedUnidirectional => ProcessStreamsBlockedFrame(reader),
                    FrameType.NewConnectionId => ProcessNewConnectionIdFrame(reader),
                    FrameType.RetireConnectionId => ProcessRetireConnectionId(reader),
                    FrameType.PathChallenge => ProcessPathChallengeFrame(reader),
                    FrameType.PathResponse => ProcessPathResponseFrame(reader),
                    FrameType.ConnectionCloseQuic => ProcessConnectionClose(reader, context),
                    FrameType.ConnectionCloseApplication => ProcessConnectionClose(reader, context),
                    FrameType.HandshakeDone => ProcessHandshakeDoneFrame(reader, context),
                    _ when (frameType & FrameType.StreamMask) == frameType => ProcessStreamFrame(reader),
                    _ => ProcessUnknownFrame(reader)
                };

                switch (result)
                {
                    case ProcessPacketResult.Ok:
                        continue;
                    case ProcessPacketResult.Error when _outboundError == null:
                        return CloseConnection(TransportErrorCode.FrameEncodingError,
                            QuicError.UnableToDeserialize, frameType);
                }

                return result;
            }

            if (ackEliciting)
            {
                var pnSpace = GetPacketNumberSpace(GetEncryptionLevel(packetType));
                pnSpace.AckElicited = true;

                // also set ack timer if wasn't set before
                if (pnSpace.NextAckTimer == long.MaxValue)
                {
                    pnSpace.NextAckTimer = context.Timestamp + Timestamp.FromMilliseconds(_localTransportParameters.MaxAckDelay) -
                                           RecoveryController.TimerGranularity;

                    // also reset global ack timer
                    ResetAckTimer();
                }
                else
                {
                    // RFC: An ACK frame SHOULD be generated for at least every second ack-
                    // eliciting packet.  This recommendation is in keeping with standard practice
                    // for TCP [RFC5681].

                    // if timer is set, then we received a second ack-eliciting frame without
                    // sending an ack back. Set timer to fire immediately to ensure ack is sent as
                    // soon as possible to the peer.
                    pnSpace.NextAckTimer = context.Timestamp;
                    _nextAckTimer = context.Timestamp;
                }
            }

            return ProcessPacketResult.Ok;
        }

        private void ResetAckTimer()
        {
            _nextAckTimer = Math.Min(_pnSpaces[0].NextAckTimer,
                Math.Min(_pnSpaces[1].NextAckTimer, _pnSpaces[2].NextAckTimer));
        }

        // TODO-RZ: remove this once all frame types are supported
        private ProcessPacketResult FrameNotSupported(FrameType type)
        {
            return CloseConnection(TransportErrorCode.InternalError, "Frame not supported", type);
        }

        private ProcessPacketResult ProcessPingFrame(QuicReader reader)
        {
            _trace?.OnPingFrame();

            // just discard the frame
            reader.ReadFrameType();
            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult DiscardPadding(QuicReader reader)
        {
            // scan until first nonzero packet
            var span = reader.PeekSpan(reader.BytesLeft);
            int paddingLength;
            for (paddingLength = 0; paddingLength < span.Length; paddingLength++)
            {
                if (span[paddingLength] != 0)
                {
                    break;
                }
            }

            reader.Advance(paddingLength);
            _trace?.OnPaddingFrame(paddingLength);

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessAckFrame(QuicReader reader, PacketType packetType, QuicSocketContext.RecvContext context)
        {
            if (!AckFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;

            long ackDelay =
                Timestamp.FromMicroseconds(frame.AckDelay * (1 << (int)_peerTransportParameters.AckDelayExponent));

            if (IsClosing) return ProcessPacketResult.Ok;

            PacketNumberSpace pnSpace = GetPacketNumberSpace(GetEncryptionLevel(packetType));

            if (frame.LargestAcknowledged >= pnSpace.NextPacketNumber || // acking future packet
                frame.LargestAcknowledged < frame.FirstAckRange) // acking negative PN
                return CloseConnection(TransportErrorCode.ProtocolViolation, QuicError.InvalidAckRange, FrameType.Ack);

            Span<RangeSet.Range> ranges = frame.AckRangeCount < 16
                ? stackalloc RangeSet.Range[(int) frame.AckRangeCount + 1]
                : new RangeSet.Range[frame.AckRangeCount + 1];

            if (!frame.TryDecodeAckRanges(ranges))
            {
              return CloseConnection(TransportErrorCode.FrameEncodingError,
                            QuicError.InvalidAckRange, frame.HasEcnCounts ? FrameType.AckWithEcn : FrameType.Ack);
            }

            var space = GetPacketSpace(packetType);
            Recovery.OnAckReceived(space, ranges, ackDelay, frame, context.Timestamp, Tls.IsHandshakeComplete);
            _trace?.OnAckFrame(frame, ackDelay);

            var ackedPackets = Recovery.GetPacketNumberSpace(space).AckedPackets;
            while (ackedPackets.TryDequeue(out var packet))
            {
                OnPacketAcked(packet, pnSpace);
                context.ReturnPacket(packet);
            }

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessResetStreamFrame(QuicReader reader)
        {
            if (!ResetStreamFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnResetStreamFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            if (!StreamHelpers.CanRead(IsServer, frame.StreamId))
                return CloseConnection(TransportErrorCode.StreamStateError,
                    QuicError.StreamNotReadable,
                    FrameType.ResetStream);

            if (!TryGetOrCreateStream(frame.StreamId, out var stream))
                return CloseConnection(TransportErrorCode.StreamLimitError,
                    QuicError.StreamsLimitViolated,
                    FrameType.ResetStream);

            // TODO-RZ: Return control flow budget

            Debug.Assert(stream!.CanRead);

            // duplicate receipt is handled internally (guarded state transitions)
            stream.ReceiveStream!.OnResetStream(frame.ApplicationErrorCode);
            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessStopSendingFrame(QuicReader reader)
        {
            if (!StopSendingFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnStopSendingFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            if (!StreamHelpers.CanWrite(IsServer, frame.StreamId))
                return CloseConnection(TransportErrorCode.StreamStateError,
                    QuicError.StreamNotWritable,
                    FrameType.StopSending);

            var stream = _streams.TryGetStream(frame.StreamId);
            // RFC: Receiving a STOP_SENDING frame for a locally-initiated stream that has not yet been created MUST be
            // treated as a connection error of type STREAM_STATE_ERROR.
            if (StreamHelpers.IsLocallyInitiated(IsServer, frame.StreamId) &&
                // Streams are Created by sending a STREAM frame, if we didn't send anything, report error
                !(stream?.SendStream?.UnsentOffset > 0))
                return CloseConnection(TransportErrorCode.StreamStateError,
                    QuicError.StreamNotCreated,
                    FrameType.StopSending);

            if (stream == null && !TryGetOrCreateStream(frame.StreamId, out stream))
                return CloseConnection(TransportErrorCode.StreamLimitError,
                    QuicError.StreamsLimitViolated,
                    FrameType.StopSending);

            Debug.Assert(stream!.CanWrite);

            // duplicate receipt is handled internally (guarded state transitions)
            stream.SendStream!.RequestAbort(frame.ApplicationErrorCode);
            _streams.MarkForUpdate(stream);

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessCryptoFrame(QuicReader reader, PacketType packetType, QuicSocketContext.RecvContext context)
        {
            if (!CryptoFrame.Read(reader, out var frame)) return ProcessPacketResult.Error;
            _trace?.OnCryptoFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            EncryptionLevel level = GetEncryptionLevel(packetType);
            var stream = GetPacketNumberSpace(level).CryptoReceiveStream;

            stream.Receive(frame.Offset, frame.CryptoData);

            // process also buffered data received earlier
            if (stream.BytesAvailable > 0)
            {
                // define a copy of level variable with smaller scope to prevent allocations in common case
                EncryptionLevel level2 = level;
                stream.Deliver(segment => { Tls.OnHandshakeDataReceived(level2, segment.Span); });
                context.HandshakeWanted = true;
            }

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessNewTokenFrame(QuicReader reader)
        {
            if (!NewTokenFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnNewTokenFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            // TODO-RZ: Implement NEW_TOKEN
            return FrameNotSupported(FrameType.NewToken);
        }

        private ProcessPacketResult ProcessMaxDataFrame(QuicReader reader)
        {
            if (!MaxDataFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnMaxDataFrame(frame);

            _sendLimits.UpdateMaxData(frame.MaximumData);
            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessMaxStreamDataFrame(QuicReader reader)
        {
            if (!MaxStreamDataFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnMaxStreamDataFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            if (!StreamHelpers.CanWrite(IsServer, frame.StreamId))
                return CloseConnection(TransportErrorCode.StreamStateError,
                    QuicError.NotInRecvState, FrameType.MaxStreamData);

            if (!TryGetOrCreateStream(frame.StreamId, out var stream))
                return CloseConnection(TransportErrorCode.StreamLimitError,
                    QuicError.StreamsLimitViolated, FrameType.MaxStreamData);

            Debug.Assert(stream!.CanWrite);

            var buffer = stream.SendStream!;
            buffer.UpdateMaxData(frame.MaximumStreamData);

            if (buffer.IsFlushable)
            {
                _streams.MarkFlushable(stream!);
            }

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessMaxStreamsFrame(QuicReader reader)
        {
            if (!MaxStreamsFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnMaxStreamsFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            if (frame.Bidirectional)
                _sendLimits.UpdateMaxStreamsBidi(frame.MaximumStreams);
            else
                _sendLimits.UpdateMaxStreamsUni(frame.MaximumStreams);

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessDataBlockedFrame(QuicReader reader)
        {
            if (!DataBlockedFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnDataBlockedFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            // TODO-RZ: Implement DATA_BLOCKED
            return FrameNotSupported(FrameType.DataBlocked);
        }

        private ProcessPacketResult ProcessStreamDataBlockedFrame(QuicReader reader)
        {
            if (!StreamDataBlockedFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnStreamDataBlockedFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            if (!TryGetOrCreateStream(frame.StreamId, out var stream))
                return CloseConnection(TransportErrorCode.StreamLimitError,
                    QuicError.StreamsLimitViolated,
                    FrameType.StreamDataBlocked);

            // TODO-RZ: Implement STREAM_DATA_BLOCKED
            return FrameNotSupported(FrameType.StreamDataBlocked);
        }

        private ProcessPacketResult ProcessStreamsBlockedFrame(QuicReader reader)
        {
            if (!StreamsBlockedFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnStreamsBlockedFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            // TODO-RZ: Implement STREAMS_BLOCKED
            return FrameNotSupported(frame.Bidirectional
                ? FrameType.StreamsBlockedBidirectional
                : FrameType.StreamsBlockedUnidirectional);
        }

        private ProcessPacketResult ProcessNewConnectionIdFrame(QuicReader reader)
        {
            if (!NewConnectionIdFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnNewConnectionIdFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            if (DestinationConnectionId!.Data.Length == 0)
            {
                return CloseConnection(TransportErrorCode.ProtocolViolation,
                    QuicError.NewConnectionIdFrameWhenZeroLengthCIDUsed, FrameType.NewConnectionId);
            }

            // RFC: If an endpoint receives a NEW_CONNECTION_ID frame that repeats a
            // previously issued connection ID with a different Stateless Reset
            // Token or a different sequence number, or if a sequence number is used
            // for different connection IDs, the endpoint MAY treat that receipt as
            // a connection error of type PROTOCOL_VIOLATION.

            var existingCid = _remoteConnectionIdCollection.FindBySequenceNumber(frame.SequenceNumber);

            if (!ReferenceEquals(_remoteConnectionIdCollection.Find(frame.ConnectionId), existingCid) ||
                 existingCid != null && existingCid.StatelessResetToken != frame.StatelessResetToken)
            {
                return CloseConnection(TransportErrorCode.ProtocolViolation,
                    QuicError.InconsistentNewConnectionIdFrame, FrameType.NewConnectionId);
            }

            if (existingCid == null)
            {
                var connectionId = new ConnectionId(
                    frame.ConnectionId.ToArray(),
                    frame.SequenceNumber,
                    frame.StatelessResetToken);

                _remoteConnectionIdCollection.Add(connectionId);
                if (NetEventSource.IsEnabled) NetEventSource.NewConnectionIdReceived(this, connectionId.Data);
            }

            if (frame.RetirePriorTo > 0)
                // TODO-RZ: implement retiring of connection ids
                return FrameNotSupported(FrameType.NewConnectionId);

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessRetireConnectionId(QuicReader reader)
        {
            if (!RetireConnectionIdFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnRetireConnectionIdFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            // TODO-RZ: Implement RETIRE_CONNECTION_ID
            return FrameNotSupported(FrameType.RetireConnectionId);
        }

        private ProcessPacketResult ProcessPathChallengeFrame(QuicReader reader)
        {
            if (!PathChallengeFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnPathChallengeFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            // TODO-RZ: Implement PATH_CHALLENGE
            return FrameNotSupported(FrameType.PathChallenge);
        }

        private ProcessPacketResult ProcessPathResponseFrame(QuicReader reader)
        {
            if (!PathChallengeFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnPathChallengeFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            // TODO-RZ: Implement PATH_RESPONSE
            return FrameNotSupported(FrameType.PathResponse);
        }

        private ProcessPacketResult ProcessConnectionClose(QuicReader reader, QuicSocketContext.RecvContext context)
        {
            if (!ConnectionCloseFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnConnectionCloseFrame(frame);

            // keep only the first error
            if (_inboundError == null)
            {
                _inboundError = new QuicError((TransportErrorCode)frame.ErrorCode, frame.ReasonPhrase,
                    frame.FrameType, frame.IsQuicError);

                if (_closingPeriodEndTimestamp == null)
                {
                    StartClosing(context.Timestamp, _inboundError);
                }

                if (_outboundError == null)
                {
                    // From RFC: An endpoint that receives a CONNECTION_CLOSE frame MAY send a single packet containing a
                    // CONNECTION_CLOSE frame before entering the draining state, using NO_ERROR code if appropriate.
                    _outboundError = new QuicError(TransportErrorCode.NoError);
                    // draining state will be entered once the error is sent.
                }
                else
                {
                    StartDraining();
                }

                if (!_connectTcs.IsSet)
                {
                    // connection will not succeed
                    _connectTcs.TryCompleteException(MakeAbortedException(_inboundError));
                }
            }

            return ProcessPacketResult.Ok;
        }


        private ProcessPacketResult ProcessStreamFrame(QuicReader reader)
        {
            var frameType = reader.PeekFrameType();
            if (!StreamFrame.Read(reader, out var frame))
                return ProcessPacketResult.Error;
            _trace?.OnStreamFrame(frame);

            if (IsClosing) return ProcessPacketResult.Ok;

            if (!StreamHelpers.CanRead(IsServer, frame.StreamId))
                return CloseConnection(TransportErrorCode.StreamStateError,
                    QuicError.StreamNotWritable,
                    frameType);

            if (!TryGetOrCreateStream(frame.StreamId, out var stream))
                return CloseConnection(TransportErrorCode.StreamLimitError,
                    QuicError.StreamsLimitViolated,
                    frameType);

            Debug.Assert(stream!.CanRead);

            var buffer = stream.ReceiveStream!;
            long writtenOffset = frame.Offset + frame.StreamData.Length;

            if (writtenOffset > buffer.Size)
            {
                // receiving data on largest offset yet, check also connection-level control flow
                ReceivedData += writtenOffset - buffer.Size;
                if (ReceivedData > _sendLimits.MaxData)
                {
                    return CloseConnection(TransportErrorCode.FlowControlError, QuicError.MaxDataViolated, frameType);
                }
            }

            // check stream-level flow control
            if (writtenOffset > buffer.MaxData)
            {
                return CloseConnection(TransportErrorCode.FlowControlError, QuicError.StreamMaxDataViolated, frameType);
            }

            if (frame.Fin)
            {
                // if trying to change final size, or setting final size lower than already sent data, report error.
                if (buffer.FinalSizeKnown && writtenOffset != buffer.Size ||
                    writtenOffset < buffer.Size)
                {
                    return CloseConnection(TransportErrorCode.FinalSizeError, QuicError.InconsistentFinalSize, frameType);
                }
            }

            // close if writing past known stream end
            if (buffer.FinalSizeKnown && writtenOffset > buffer.Size)
            {
                return CloseConnection(TransportErrorCode.FinalSizeError, QuicError.WritingPastFinalSize, frameType);
            }

            // RFC: STREAM frames received after sending STOP_SENDING are still counted
            // toward connection and stream flow control, even though these frames
            // can be discarded upon receipt.
            //
            // we also discard any data received after receiving RESET_STREAM, which might occur
            // due to packet reordering.
            if (buffer.StreamState <= RecvStreamState.SizeKnown)
            {
                buffer.Receive(frame.Offset, frame.StreamData, frame.Fin);
            }

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessHandshakeDoneFrame(QuicReader reader, QuicSocketContext.RecvContext context)
        {
            _trace?.OnHandshakeDoneFrame();

            // frame not being allowed to be sent by client is handled in IsPacketAllowed
            Debug.Assert(!IsServer);

            reader.ReadFrameType(); // there are no more data, just the frame type identifier.

            _handshakeDoneReceived = true;

            // An endpoint MUST discard handshake keys when TLS handshake is complete.
            DropPacketNumberSpace(PacketSpace.Handshake, context.SentPacketPool);

            SignalConnected();

            return ProcessPacketResult.Ok;
        }

        private ProcessPacketResult ProcessUnknownFrame(QuicReader reader)
        {
            int length = reader.BytesLeft;
            FrameType frameType = reader.ReadFrameType();
            _trace?.OnUnknownFrame((long) frameType, length);
            return CloseConnection(TransportErrorCode.FrameEncodingError, QuicError.UnknownFrameType, frameType);
        }

        private void WriteFrames(QuicWriter writer, PacketType packetType, EncryptionLevel level, QuicSocketContext.SendContext context)
        {
            var pnSpace = GetPacketNumberSpace(level);

            // TODO-RZ other frames

            // start by non ack-eliciting frames
            WriteConnectionCloseFrame(writer, context);
            if (_outboundError != null) return;
            WriteAckFrame(writer, pnSpace, context);

            // we can simply track if this packet by tracking the written offset.
            int writtenAfterNonAckEliciting = writer.BytesWritten;

            if (writer.BytesAvailable > 0 && IsServer && packetType == PacketType.OneRtt &&
                Tls.IsHandshakeComplete && !_handshakeDoneReceived)
            {
                _trace?.OnHandshakeDoneFrame();
                writer.WriteFrameType(FrameType.HandshakeDone);
                // no data

                SignalConnected();
                context.SentPacket.HandshakeDoneSent = true;

                // handshake is done
                DropPacketNumberSpace(PacketSpace.Handshake, context.SentPacketPool);
            }

            if (writer.BytesAvailable > 0 && _pingWanted)
            {
                _trace?.OnPingFrame();
                writer.WriteFrameType(FrameType.Ping);
                // no data
                _pingWanted = false;
            }

            WriteCryptoFrames(writer, pnSpace, context);

            if (packetType == PacketType.OneRtt)
            {
                WriteStreamUpdateFrames(writer, context);
                WriteMaxDataFrame(writer, context);
                WriteStreamFrames(writer, context);
            }

            if (writer.BytesWritten > writtenAfterNonAckEliciting)
            {
                // ack-eliciting frame was definitely sent.
                context.SentPacket.InFlight = true;
                context.SentPacket.AckEliciting = true;
            }
        }

        private bool ShouldSendConnectionClose(long timestamp)
        {
            if (_outboundError == null)
            {
                // nothing to send
                return false;
            }

            // TODO-RZ: During the closing period, an endpoint SHOULD limit the number of packets it generates
            // containing a CONNECTION_CLOSE frame. For instance, wait progressively increasing number of packets or
            // amount of time before responding.
            return _lastConnectionCloseSentTimestamp < timestamp;
        }

        private void WriteConnectionCloseFrame(QuicWriter writer, QuicSocketContext.SendContext context)
        {
            if (!ShouldSendConnectionClose(context.Timestamp))
            {
                return;
            }

            if (_closingPeriodEndTimestamp == null)
            {
                // After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing state.
                StartClosing(context.Timestamp, _outboundError!);
            }

            var frame = new ConnectionCloseFrame((long)_outboundError!.ErrorCode,
                _outboundError.IsQuicError,
                _outboundError.FrameType,
                _outboundError.ReasonPhrase);

            if (frame.GetSerializedLength() > writer.BytesAvailable)
            {
                // we can't fit the frame into the packet, wait for next time
                return;
            }

            ConnectionCloseFrame.Write(writer, frame);
            _trace?.OnConnectionCloseFrame(frame);
            _lastConnectionCloseSentTimestamp = context.Timestamp;

            if (_inboundError != null)
            {
                // We should already be draining, but RFC allows sending one packet to make closing faster. That packet
                // is going to be sent with this CONNECTION_CLOSE frame
                StartDraining();
            }
        }

        private void WriteCryptoFrames(QuicWriter writer, PacketNumberSpace pnSpace, QuicSocketContext.SendContext context)
        {
            // assume 2 * 2 bytes for offset and length and 1 B for type
            const int minSize = 5;
            while (writer.BytesAvailable > minSize)
            {
                if (!pnSpace.CryptoSendStream.IsFlushable)
                    return;

                (long offset, long count) = pnSpace.CryptoSendStream.GetNextSendableRange();

                count = Math.Min(count, (long)writer.BytesAvailable - minSize);
                var destination = CryptoFrame.ReservePayloadBuffer(writer, offset, count);
                pnSpace.CryptoSendStream.CheckOut(destination);
                _trace?.OnCryptoFrame(new CryptoFrame(offset, destination));

                context.SentPacket.StreamFrames.Add(
                    SentPacket.StreamFrameHeader.ForCryptoStream(offset, (int) count));
            }
        }

        private void WriteAckFrame(QuicWriter writer, PacketNumberSpace pnSpace, QuicSocketContext.SendContext context)
        {
            var ranges = pnSpace.UnackedPacketNumbers;

            if (ranges.Count == 0)
            {
                return; // no need for ack now
            }

            pnSpace.LastAckSentTimestamp = context.Timestamp;

            // reset ack timer
            pnSpace.NextAckTimer = long.MaxValue;
            ResetAckTimer();

            Debug.Assert(ranges.Count > 0); // implied by AckElicited
            Debug.Assert(pnSpace.LargestReceivedPacketTimestamp != 0);

            long ackDelayMicroSeconds = Timestamp.GetMicroseconds(context.Timestamp - pnSpace.LargestReceivedPacketTimestamp);
            // sanity check
            ackDelayMicroSeconds = Math.Max(0, ackDelayMicroSeconds);

            long ackDelay = ackDelayMicroSeconds >> (int)_localTransportParameters.AckDelayExponent;

            long largest = ranges.GetMax();
            var firstRange = ranges[^1];

            int written = 0;
            int lengthEstimate = ranges.Count * 2 * 4; // assume worst case encoding

            Span<byte> ackRangesRaw = lengthEstimate <= 512
                ? stackalloc byte[lengthEstimate]
                : new byte[lengthEstimate];

            long prevSmallestAcked = firstRange.Start;
            int overhead = AckFrame.GetOverhead(largest, ackDelay, ranges.Count, firstRange.Length - 1);

            // write as many ranges as possible
            int rangesSent = 0;
            for (int i = ranges.Count - 2; i >= 0; i--)
            {
                var range = ranges[i];

                long nextLargestAcked = range.End;

                // the numbers are always encoded as one lesser, meaning sending 0 in gap means actually 1,
                // implying that     nextLargestAcked = prevSmallestAck - gap - 2

                long gap = prevSmallestAcked - nextLargestAcked - 2;
                long ack = range.Length - 1;

                int rangeWireLength = 0;
                rangeWireLength += QuicPrimitives.WriteVarInt(ackRangesRaw.Slice(written + rangeWireLength), gap);
                rangeWireLength += QuicPrimitives.WriteVarInt(ackRangesRaw.Slice(written + rangeWireLength), ack);

                if (written + overhead + rangeWireLength > writer.BytesAvailable)
                {
                    // cannot fit more
                    break;
                }

                prevSmallestAcked = ranges[i].Start;
                // record that the range has been sent
                context.SentPacket.AckedRanges.Add(range.Start, range.End);
                rangesSent++;
                written += rangeWireLength;
            }

            if (written + overhead <= writer.BytesAvailable)
            {
                context.SentPacket.AckedRanges.Add(firstRange.Start, firstRange.End);

                // TODO-RZ implement ECN counts
                var frame = new AckFrame(largest, ackDelay, rangesSent,
                    firstRange.Length - 1, ackRangesRaw.Slice(0, written),
                    false, 0, 0, 0);
                AckFrame.Write(writer, frame);
                _trace?.OnAckFrame(frame, ackDelayMicroSeconds);

                pnSpace.AckElicited = false;
            }
        }

        private void WriteStreamUpdateFrames(QuicWriter writer, QuicSocketContext.SendContext context)
        {
            ManagedQuicStream? stream;
            while (writer.BytesAvailable > 0 && (stream = _streams.GetFirstStreamForUpdate()) != null)
            {
                if (!WriteStreamMaxDataFrame(writer, stream, context) ||
                    !WriteStopSendingFrame(writer, stream, context) ||
                    !WriteResetStreamFrame(writer, stream, context))
                {
                    // some update was not written to the packet due to size constraints, queue stream for retry
                    _streams.MarkForUpdate(stream);
                    break;
                }
            }
        }

        private bool WriteStreamMaxDataFrame(QuicWriter writer, ManagedQuicStream stream,
            QuicSocketContext.SendContext context)
        {
            var buffer = stream.ReceiveStream;

            if (buffer == null ||
                // only in Receive state do the frames make any sense
                buffer.StreamState != RecvStreamState.Receive ||
                !buffer.ShouldUpdateMaxData())
            {
                // nothing to update
                return true;
            }

            var frame = new MaxStreamDataFrame(stream.StreamId, buffer.MaxData);
            if (writer.BytesAvailable < frame.GetSerializedLength())
            {
                return false;
            }

            MaxStreamDataFrame.Write(writer, frame);
            _trace?.OnMaxStreamDataFrame(frame);
            context.SentPacket.MaxStreamDataFrames.Add(frame);

            return true;
        }

        private bool WriteStopSendingFrame(QuicWriter writer, ManagedQuicStream stream,
            QuicSocketContext.SendContext context)
        {
            var buffer = stream.ReceiveStream;

            if (buffer?.Error == null ||
                buffer.StreamState != RecvStreamState.WantStopSending)
            {
                // nothing to update
                return true;
            }

            var frame = new StopSendingFrame(stream.StreamId, buffer.Error.Value);
            if (writer.BytesAvailable < frame.GetSerializedLength())
            {
                return false;
            }

            StopSendingFrame.Write(writer, frame);
            _trace?.OnStopSendingFrame(frame);
            context.SentPacket.StreamsStopped.Add(frame.StreamId);
            buffer.OnStopSendingSent();

            return true;
        }

        private bool WriteResetStreamFrame(QuicWriter writer, ManagedQuicStream stream,
            QuicSocketContext.SendContext context)
        {
            var buffer = stream.SendStream;

            if (buffer?.Error == null ||
                buffer.StreamState != SendStreamState.WantReset)
            {
                // nothing to update
                return true;
            }

            var frame = new ResetStreamFrame(stream.StreamId, buffer.Error.Value, buffer.UnsentOffset);
            if (writer.BytesAvailable < frame.GetSerializedLength())
            {
                return false;
            }

            ResetStreamFrame.Write(writer, frame);
            _trace?.OnResetStreamFrame(frame);
            context.SentPacket.StreamsReset.Add(stream.StreamId);
            buffer.OnResetSent();

            return true;
        }

        private void WriteMaxDataFrame(QuicWriter writer, QuicSocketContext.SendContext context)
        {
            // Update Max Data if the sender has surpassed at least half the data window
            if (MaxDataFrameSent ||
                _receiveLimits.MaxData - _receiveLimitsAtPeer.MaxData < _receiveLimitsAtPeer.MaxData - ReceivedData)
            {
                return;
            }

            var frame = new MaxDataFrame(_receiveLimits.MaxData);

            if (writer.BytesAvailable <= frame.GetSerializedLength())
            {
                return;
            }

            MaxDataFrame.Write(writer, frame);
            _trace?.OnMaxDataFrame(frame);
            context.SentPacket.MaxDataFrame = frame;
            MaxDataFrameSent = true;
        }

        private void WriteStreamFrames(QuicWriter writer, QuicSocketContext.SendContext context)
        {
            ManagedQuicStream? stream;
            bool written = false;

            while (writer.BytesAvailable > StreamFrame.MinSize && (stream = _streams.GetFirstFlushableStream()) != null)
            {
                var buffer = stream!.SendStream!;

                if (!buffer.IsFlushable && !buffer.SizeKnown)
                {
                    // race condition, should not happen terribly often
                    continue;
                }

                (long offset, long count) = buffer.GetNextSendableRange();

                // send only as much data as can fit into the packet
                int overhead = StreamFrame.GetOverheadLength(stream.StreamId, offset, count);
                count = Math.Min(count, writer.BytesAvailable - overhead);

                // respect connection-level control flow
                long flowControlAvailable = _sendLimits.MaxData - SentData;
                count = Math.Min(count, buffer.UnsentOffset + flowControlAvailable - offset);

                // if size is known, WrittenBytes is no longer mutable
                bool fin = buffer.SizeKnown && buffer.WrittenBytes == offset + count;

                if (count > 0 || fin && !buffer.FinAcked)
                {
                    var payloadDestination = StreamFrame.ReservePayloadBuffer(writer, stream!.StreamId, offset, (int)count, fin);
                    _trace?.OnStreamFrame(new StreamFrame(stream!.StreamId, offset, fin, payloadDestination));

                    // add the newly sent data to the flow control counter
                    SentData += Math.Max(0, offset + count - buffer.UnsentOffset);
                    buffer.CheckOut(payloadDestination);

                    // record sent data
                    context.SentPacket.StreamFrames.Add(
                        new SentPacket.StreamFrameHeader(stream!.StreamId, offset, (int) count, fin));

                    written = true;
                }

                // if there is more data to sent, put the stream back to queue
                if (buffer.HasBytesToSend)
                {
                    _streams.MarkFlushable(stream!);
                }

                if (count <= 0)
                {
                    // no more data can fit into this packet.
                    break;
                }
            }

            // TODO-RZ: This may not be as precise as RFC requires
            Recovery.IsApplicationLimited = !written;
        }
    }
}
