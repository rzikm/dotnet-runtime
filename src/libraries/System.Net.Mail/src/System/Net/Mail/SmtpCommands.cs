// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Net.Mime;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading.Tasks;

namespace System.Net.Mail
{
    internal static class CheckCommand
    {
        internal static SmtpStatusCode Send(SmtpConnection conn, out string response)
        {
            conn.Flush();
            SmtpReplyReader reader = conn.Reader!.GetNextReplyReader();
            LineInfo info = reader.ReadLine();
            response = info.Line;
            reader.Close();
            return info.StatusCode;
        }

        internal static async Task<LineInfo> SendAsync(SmtpConnection conn)
        {
            await conn.FlushAsync().ConfigureAwait(false);
            using SmtpReplyReader reader = conn.Reader!.GetNextReplyReader();
            return await reader.ReadLineAsync().ConfigureAwait(false);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn), callback, state);
        }

        internal static object EndSend(IAsyncResult result, out string response)
        {
            LineInfo info = TaskToAsyncResult.End<LineInfo>(result);
            response = info.Line;
            return info.StatusCode;
        }
    }

    internal static class ReadLinesCommand
    {
        internal static async Task<LineInfo[]> SendAsync(SmtpConnection conn)
        {
            await conn.FlushAsync().ConfigureAwait(false);
            return await conn.Reader!.GetNextReplyReader().ReadLinesAsync().ConfigureAwait(false);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn), callback, state);
        }

        internal static LineInfo[] EndSend(IAsyncResult result)
        {
            return TaskToAsyncResult.End<LineInfo[]>(result);
        }

        internal static LineInfo[] Send(SmtpConnection conn)
        {
            conn.Flush();
            return conn.Reader!.GetNextReplyReader().ReadLines();
        }
    }

    internal static class AuthCommand
    {
        internal static async Task<LineInfo> SendAsync(SmtpConnection conn, string type, string message)
        {
            PrepareCommand(conn, type, message);
            LineInfo[] lines = await ReadLinesCommand.SendAsync(conn).ConfigureAwait(false);
            return CheckResponse(lines);
        }

        internal static async Task<LineInfo> SendAsync(SmtpConnection conn, string? message)
        {
            PrepareCommand(conn, message);
            LineInfo[] lines = await ReadLinesCommand.SendAsync(conn).ConfigureAwait(false);
            return CheckResponse(lines);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, string type, string message, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn, type, message), callback, state);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, string? message, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn, message), callback, state);
        }

        internal static LineInfo EndSend(IAsyncResult result)
        {
            return TaskToAsyncResult.End<LineInfo>(result);
        }

        private static LineInfo CheckResponse(LineInfo[] lines)
        {
            if (lines == null || lines.Length == 0)
            {
                throw new SmtpException(SR.SmtpAuthResponseInvalid);
            }
            System.Diagnostics.Debug.Assert(lines.Length == 1, "Did not expect more than one line response for auth command");
            return lines[0];
        }

        private static void PrepareCommand(SmtpConnection conn, string type, string message)
        {
            conn.BufferBuilder.Append(SmtpCommands.Auth.Span);
            conn.BufferBuilder.Append(type);
            conn.BufferBuilder.Append((byte)' ');
            conn.BufferBuilder.Append(message);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }

        private static void PrepareCommand(SmtpConnection conn, string? message)
        {
            conn.BufferBuilder.Append(message);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }

        internal static LineInfo Send(SmtpConnection conn, string type, string message)
        {
            PrepareCommand(conn, type, message);
            return CheckResponse(ReadLinesCommand.Send(conn));
        }

        internal static LineInfo Send(SmtpConnection conn, string? message)
        {
            PrepareCommand(conn, message);
            return CheckResponse(ReadLinesCommand.Send(conn));
        }
    }

    internal static class DataCommand
    {
        internal static async Task SendAsync(SmtpConnection conn)
        {
            PrepareCommand(conn);
            LineInfo info = await CheckCommand.SendAsync(conn).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn), callback, state);
        }

        internal static void EndSend(IAsyncResult result)
        {
            TaskToAsyncResult.End(result);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string serverResponse)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.StartMailInput:
                    {
                        return;
                    }
                case SmtpStatusCode.LocalErrorInProcessing:
                case SmtpStatusCode.TransactionFailed:
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, serverResponse);
                        }

                        throw new SmtpException(statusCode, serverResponse, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.Data);
        }

        internal static void Send(SmtpConnection conn)
        {
            PrepareCommand(conn);
            string response;
            SmtpStatusCode statusCode = CheckCommand.Send(conn, out response);
            CheckResponse(statusCode, response);
        }
    }

    internal static class DataStopCommand
    {
        private static void CheckResponse(SmtpStatusCode statusCode, string serverResponse)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.Ok:
                    {
                        return;
                    }
                case SmtpStatusCode.ExceededStorageAllocation:
                case SmtpStatusCode.TransactionFailed:
                case SmtpStatusCode.LocalErrorInProcessing:
                case SmtpStatusCode.InsufficientStorage:
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, serverResponse);
                        }

                        throw new SmtpException(statusCode, serverResponse, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.DataStop);
        }
        internal static void Send(SmtpConnection conn)
        {
            PrepareCommand(conn);
            string response;
            SmtpStatusCode statusCode = CheckCommand.Send(conn, out response);
            CheckResponse(statusCode, response);
        }
    }

    internal static class EHelloCommand
    {
        internal static async Task<string[]> SendAsync(SmtpConnection conn, string domain)
        {
            PrepareCommand(conn, domain);
            LineInfo[] lines = await ReadLinesCommand.SendAsync(conn).ConfigureAwait(false);
            return CheckResponse(lines);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, string domain, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn, domain), callback, state);
        }

        internal static string[] EndSend(IAsyncResult result)
        {
            return TaskToAsyncResult.End<string[]>(result);
        }

        private static string[] CheckResponse(LineInfo[] lines)
        {
            if (lines == null || lines.Length == 0)
            {
                throw new SmtpException(SR.SmtpEhloResponseInvalid);
            }
            if (lines[0].StatusCode != SmtpStatusCode.Ok)
            {
                if ((int)lines[0].StatusCode < 400)
                {
                    throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, lines[0].Line);
                }

                throw new SmtpException(lines[0].StatusCode, lines[0].Line, true);
            }
            string[] extensions = new string[lines.Length - 1];
            for (int i = 1; i < lines.Length; i++)
            {
                extensions[i - 1] = lines[i].Line;
            }
            return extensions;
        }

        private static void PrepareCommand(SmtpConnection conn, string domain)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.EHello);
            conn.BufferBuilder.Append(domain);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }

        internal static string[] Send(SmtpConnection conn, string domain)
        {
            PrepareCommand(conn, domain);
            return CheckResponse(ReadLinesCommand.Send(conn));
        }
    }

    internal static class HelloCommand
    {
        internal static async Task SendAsync(SmtpConnection conn, string domain)
        {
            PrepareCommand(conn, domain);
            LineInfo info = await CheckCommand.SendAsync(conn).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, string domain, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn, domain), callback, state);
        }

        internal static void EndSend(IAsyncResult result)
        {
            TaskToAsyncResult.End(result);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string serverResponse)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.Ok:
                    {
                        return;
                    }
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, serverResponse);
                        }

                        throw new SmtpException(statusCode, serverResponse, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn, string domain)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.Hello);
            conn.BufferBuilder.Append(domain);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }

        internal static void Send(SmtpConnection conn, string domain)
        {
            PrepareCommand(conn, domain);
            string response;
            SmtpStatusCode statusCode = CheckCommand.Send(conn, out response);
            CheckResponse(statusCode, response);
        }
    }

    internal static class StartTlsCommand
    {
        internal static async Task SendAsync(SmtpConnection conn)
        {
            PrepareCommand(conn);
            LineInfo info = await CheckCommand.SendAsync(conn).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn), callback, state);
        }

        internal static void EndSend(IAsyncResult result)
        {
            TaskToAsyncResult.End(result);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string response)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.ServiceReady:
                    {
                        return;
                    }

                case SmtpStatusCode.ClientNotPermitted:
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, response);
                        }

                        throw new SmtpException(statusCode, response, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.StartTls);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }

        internal static void Send(SmtpConnection conn)
        {
            PrepareCommand(conn);
            string response;
            SmtpStatusCode statusCode = CheckCommand.Send(conn, out response);
            CheckResponse(statusCode, response);
        }
    }

    internal static class MailCommand
    {
        internal static async Task SendAsync(SmtpConnection conn, ReadOnlyMemory<byte> command, MailAddress from, bool allowUnicode)
        {
            PrepareCommand(conn, command, from, allowUnicode);
            LineInfo info = await CheckCommand.SendAsync(conn).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, ReadOnlyMemory<byte> command, MailAddress from, bool allowUnicode, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn, command, from, allowUnicode), callback, state);
        }

        internal static void EndSend(IAsyncResult result)
        {
            TaskToAsyncResult.End(result);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string response)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.Ok:
                    {
                        return;
                    }
                case SmtpStatusCode.ExceededStorageAllocation:
                case SmtpStatusCode.LocalErrorInProcessing:
                case SmtpStatusCode.InsufficientStorage:
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, response);
                        }

                        throw new SmtpException(statusCode, response, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn, ReadOnlyMemory<byte> command, MailAddress from, bool allowUnicode)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }
            conn.BufferBuilder.Append(command);
            string fromString = from.GetSmtpAddress(allowUnicode);
            conn.BufferBuilder.Append(fromString, allowUnicode);
            if (allowUnicode)
            {
                conn.BufferBuilder.Append(" BODY=8BITMIME SMTPUTF8");
            }
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }

        internal static void Send(SmtpConnection conn, ReadOnlyMemory<byte> command, MailAddress from, bool allowUnicode)
        {
            PrepareCommand(conn, command, from, allowUnicode);
            string response;
            SmtpStatusCode statusCode = CheckCommand.Send(conn, out response);
            CheckResponse(statusCode, response);
        }
    }

    internal static class RecipientCommand
    {
        internal static async Task<bool> SendAsync(SmtpConnection conn, string to)
        {
            PrepareCommand(conn, to);
            LineInfo info = await CheckCommand.SendAsync(conn).ConfigureAwait(false);
            return CheckResponse(info.StatusCode, info.Line);
        }

        internal static IAsyncResult BeginSend(SmtpConnection conn, string to, AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(SendAsync(conn, to), callback, state);
        }

        internal static bool EndSend(IAsyncResult result, out string response)
        {
            LineInfo info = TaskToAsyncResult.End<LineInfo>(result);
            response = info.Line;
            return CheckResponse(info.StatusCode, response);
        }

        private static bool CheckResponse(SmtpStatusCode statusCode, string response)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.Ok:
                case SmtpStatusCode.UserNotLocalWillForward:
                    {
                        return true;
                    }
                case SmtpStatusCode.MailboxUnavailable:
                case SmtpStatusCode.UserNotLocalTryAlternatePath:
                case SmtpStatusCode.ExceededStorageAllocation:
                case SmtpStatusCode.MailboxNameNotAllowed:
                case SmtpStatusCode.MailboxBusy:
                case SmtpStatusCode.InsufficientStorage:
                    {
                        return false;
                    }
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, response);
                        }

                        throw new SmtpException(statusCode, response, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn, string to)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.Recipient);
            conn.BufferBuilder.Append(to, true); // Unicode validation was done prior
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }

        internal static bool Send(SmtpConnection conn, string to, out string response)
        {
            PrepareCommand(conn, to);
            SmtpStatusCode statusCode = CheckCommand.Send(conn, out response);
            return CheckResponse(statusCode, response);
        }
    }

    internal static class QuitCommand
    {
        private static void PrepareCommand(SmtpConnection conn)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.Quit);
        }

        internal static void Send(SmtpConnection conn)
        {
            PrepareCommand(conn);

            // We simply flush and don't read the response
            // to avoid blocking call that will impact users
            // that are using async api, since this code
            // will run on Dispose()
            conn.Flush();
        }
    }

    internal static class SmtpCommands
    {
        internal static ReadOnlyMemory<byte> Auth => "AUTH "u8.ToArray();
        internal static ReadOnlyMemory<byte> CRLF => "\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Data => "DATA\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> DataStop => "\r\n.\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> EHello => "EHLO "u8.ToArray();
        internal static ReadOnlyMemory<byte> Expand => "EXPN "u8.ToArray();
        internal static ReadOnlyMemory<byte> Hello => "HELO "u8.ToArray();
        internal static ReadOnlyMemory<byte> Help => "HELP"u8.ToArray();
        internal static ReadOnlyMemory<byte> Mail => "MAIL FROM:"u8.ToArray();
        internal static ReadOnlyMemory<byte> Noop => "NOOP\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Quit => "QUIT\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Recipient => "RCPT TO:"u8.ToArray();
        internal static ReadOnlyMemory<byte> Reset => "RSET\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Send => "SEND FROM:"u8.ToArray();
        internal static ReadOnlyMemory<byte> SendAndMail => "SAML FROM:"u8.ToArray();
        internal static ReadOnlyMemory<byte> SendOrMail => "SOML FROM:"u8.ToArray();
        internal static ReadOnlyMemory<byte> Turn => "TURN\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Verify => "VRFY "u8.ToArray();
        internal static ReadOnlyMemory<byte> StartTls => "STARTTLS"u8.ToArray();
    }

    internal readonly struct LineInfo
    {
        internal LineInfo(SmtpStatusCode statusCode, string line)
        {
            StatusCode = statusCode;
            Line = line;
        }
        internal string Line { get; }
        internal SmtpStatusCode StatusCode { get; }
    }
}
