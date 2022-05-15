// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Net.Quic.Implementations.Managed.Internal.Tls.OpenSsl;
using System.Net.Security;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static unsafe partial class OpenSslQuic
    {
        internal const int CRYPTO_EX_INDEX_SSL = 0;
        internal const int SSL_TLSEXT_ERR_NOACK = 3;
        internal const int SSL_TLSEXT_ERR_OK = 0;

        // TODO: Move to CryptoNative
        internal const string Ssl = "libssl.so.1.1";
        internal const string Crypto = "libcrypto.so.1.1";

        private const string EntryPointPrefix = "";

        internal static bool IsSupported { get; }

        static OpenSslQuic()
        {
            IntPtr ctx = IntPtr.Zero;
            IntPtr ssl = IntPtr.Zero;

            try
            {
                ctx = SslCtxNew(TlsMethod());
                ssl = SslNew(ctx);

                // this function is present only in the modified OpenSSL library
                SslSetQuicMethod(ssl, IntPtr.Zero);

                IsSupported = true;
            }
            // propagate the exception if the user explicitly states to use the OpenSSL based implementation
            catch (Exception e) when (e is DllNotFoundException || e is EntryPointNotFoundException)
            {
                if (Environment.GetEnvironmentVariable("DOTNETQUIC_OPENSSL") != null)
                {
                    throw new NotSupportedException(
                        "QUIC via OpenSSL is not available. Make sure the appropriate OpenSSL version is in PATH", e);
                }
                // nope
                IsSupported = false;
            }


            // Free up the allocated native resources
            if (ssl != IntPtr.Zero)
                SslFree(ssl);

            if (ctx != IntPtr.Zero)
                SslCtxFree(ctx);
        }

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "TLS_method")]
        internal static partial IntPtr TlsMethod();

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "CRYPTO_get_ex_new_index")]
        internal static partial int CryptoGetExNewIndex(int classIndex, long argl, IntPtr argp, IntPtr newFunc,
            IntPtr dupFunc, IntPtr freeFunc);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ErrorPrintCallback(byte* str, UIntPtr len, IntPtr u);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_new")]
        internal static partial IntPtr SslCtxNew(IntPtr method);


        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_free")]
        internal static partial void SslCtxFree(IntPtr ctx);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_set_client_cert_cb")]
        internal static partial IntPtr SslCtxSetClientCertCb(IntPtr method);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_new")]
        internal static partial IntPtr SslNew(IntPtr ctx);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_free")]
        internal static partial void SslFree(IntPtr ssl);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_use_certificate_file")]
        internal static partial int SslUseCertificateFile(IntPtr ssl, [MarshalAs(UnmanagedType.LPStr
            )]
            string file, SslFiletype type);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_use_PrivateKey_file")]
        internal static partial int SslUsePrivateKeyFile(IntPtr ssl, [MarshalAs(UnmanagedType.LPStr
            )]
            string file, SslFiletype type);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_use_cert_and_key")]
        internal static partial int SslUseCertAndKey(IntPtr ssl, IntPtr x509, IntPtr privateKey, IntPtr caChain, int doOverride);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_use_certificate")]
        internal static partial int SslUseCertificate(IntPtr ssl, IntPtr x509);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_version")]
        internal static partial byte* SslGetVersion(IntPtr ssl);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_quic_method")]
        internal static partial int SslSetQuicMethod(IntPtr ssl, IntPtr methods);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_accept_state")]
        internal static partial int SslSetAcceptState(IntPtr ssl);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_connect_state")]
        internal static partial int SslSetConnectState(IntPtr ssl);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_do_handshake")]
        internal static partial int SslDoHandshake(IntPtr ssl);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_ctrl")]
        internal static partial int SslCtrl(IntPtr ssl, SslCtrlCommand cmd, long larg, IntPtr parg);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_callback_ctrl")]
        internal static partial int SslCallbackCtrl(IntPtr ssl, SslCtrlCommand cmd, IntPtr fp);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_callback_ctrl")]
        internal static partial int SslCtxCallbackCtrl(IntPtr ctx, SslCtrlCommand cmd, IntPtr fp);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_error")]
        internal static partial int SslGetError(IntPtr ssl, int code);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_provide_quic_data")]
        internal static partial int SslProvideQuicData(IntPtr ssl, OpenSslEncryptionLevel level, byte* data, IntPtr len);

        internal static int SslProvideQuicData(IntPtr ssl, OpenSslEncryptionLevel level, ReadOnlySpan<byte> data)
        {
            fixed (byte* pData = data)
            {
                return SslProvideQuicData(ssl, level, pData, new IntPtr(data.Length));
            }
        }

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_ex_data")]
        internal static partial int SslSetExData(IntPtr ssl, int idx, IntPtr data);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_ex_data")]
        internal static partial IntPtr SslGetExData(IntPtr ssl, int idx);

        internal static int SslSetTlsExtHostName(IntPtr ssl, string hostname)
        {
            var addr = Marshal.StringToHGlobalAnsi(hostname);
            const long TLSEXT_NAMETYPE_host_name = 0;
            int res = SslCtrl(ssl, SslCtrlCommand.SetTlsextHostname, TLSEXT_NAMETYPE_host_name, addr);
            Marshal.FreeHGlobal(addr);
            return res;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int TlsExtServernameCallback(IntPtr ssl, int* al, IntPtr arg);

        internal static int SslCtxSetTlsExtServernameCallback(IntPtr ctx, TlsExtServernameCallback callback)
        {
            var addr = Marshal.GetFunctionPointerForDelegate(callback);
            return SslCtxCallbackCtrl(ctx, SslCtrlCommand.SetTlsextServernameCb, addr);
        }

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_quic_transport_params")]
        internal static partial int SslSetQuicTransportParams(IntPtr ssl, byte* param, IntPtr length);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_peer_quic_transport_params")]
        internal static partial int SslGetPeerQuicTransportParams(IntPtr ssl, out byte* param, out IntPtr length);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_quic_write_level")]
        internal static partial OpenSslEncryptionLevel SslQuicWriteLevel(IntPtr ssl);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_is_init_finished")]
        internal static partial int SslIsInitFinished(IntPtr ssl);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_current_cipher")]
        internal static partial IntPtr SslGetCurrentCipher(IntPtr ssl);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CIPHER_get_protocol_id")]
        internal static partial ushort SslCipherGetProtocolId(IntPtr cipher);

        internal static TlsCipherSuite SslGetCipherId(IntPtr ssl)
        {
            var cipher = SslGetCurrentCipher(ssl);
            return (TlsCipherSuite)SslCipherGetProtocolId(cipher);
        }

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_ciphersuites")]
        internal static partial int SslSetCiphersuites(IntPtr ssl, byte* list);

        internal static int SslSetCiphersuites(IntPtr ssl, string list)
        {
            var ptr = Marshal.StringToHGlobalAnsi(list);
            int result = SslSetCiphersuites(ssl, (byte*)ptr.ToPointer());
            Marshal.FreeHGlobal(ptr);
            return result;
        }

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_cipher_list")]
        internal static partial int SslSetCipherList(IntPtr ssl, byte* list);

        internal static int SslSetCipherList(IntPtr ssl, string list)
        {
            var ptr = Marshal.StringToHGlobalAnsi(list);
            int result = SslSetCipherList(ssl, (byte*)ptr.ToPointer());
            Marshal.FreeHGlobal(ptr);
            return result;
        }

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_cipher_list")]
        internal static partial IntPtr SslGetCipherList(IntPtr ssl, int priority);

        internal static List<string> SslGetCipherList(IntPtr ssl)
        {
            var list = new List<string>();

            int priority = 0;
            IntPtr ptr;
            while ((ptr = SslGetCipherList(ssl, priority)) != IntPtr.Zero)
            {
                list.Add(Marshal.PtrToStringAnsi(ptr)!);
                priority++;
            }

            return list;
        }

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_alpn_protos")]
        internal static partial int SslSetAlpnProtos(IntPtr ssl, IntPtr protosStr, int protosLen);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get0_alpn_selected")]
        internal static partial int SslGet0AlpnSelected(IntPtr ssl, out IntPtr data, out int len);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_set_alpn_select_cb")]
        internal static partial int SslCtxSetAlpnSelectCb(IntPtr ctx, IntPtr cb, IntPtr arg);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int AlpnSelectCb(IntPtr ssl, byte** pOut, byte* outLen, byte* pIn, int inLen, IntPtr arg);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_peer_certificate")]
        internal static partial IntPtr SslGetPeerCertificate(IntPtr ssl);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_s_mem")]
        internal static partial IntPtr BioSMem();

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_new")]
        internal static partial IntPtr BioNew(IntPtr bioMethod);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_new_mem_buf")]
        internal static partial IntPtr BioNewMemBuf(byte* buf, int len);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_free")]
        internal static partial void BioFree(IntPtr bio);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_write")]
        internal static partial int BioWrite(IntPtr bio, byte* data, int dlen);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "PEM_read_bio_X509")]
        internal static partial IntPtr PemReadBioX509(IntPtr bio, IntPtr pOut, IntPtr pemPasswordCb, IntPtr u);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "d2i_X509")]
        internal static partial IntPtr D2iX509(IntPtr pOut, ref byte* data, int len);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "d2i_PKCS12_bio")]
        internal static partial IntPtr D2iPkcs12(IntPtr pOut, ref byte* data, int len);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "PKCS12_parse")]
        internal static partial int Pkcs12Parse(IntPtr pkcs, IntPtr pass, out IntPtr key, out IntPtr cert, out IntPtr caStack);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "PKCS12_free")]
        internal static partial void Pkcs12Free(IntPtr pkcs);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "X509_free")]
        internal static partial void X509Free(IntPtr x509);

        [LibraryImport(Crypto, EntryPoint = EntryPointPrefix + "EVP_PKEY_free")]
        internal static partial void EvpPKeyFree(IntPtr evpKey);

        // [LibraryImport(Libraries.Crypto, EntryPoint = LibPrefix + "OPENSSL_sk_kj")]
        // internal static partial void SkX509Free(IntPtr stack);

        [LibraryImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_servername")]
        internal static partial IntPtr SslGetServername(IntPtr ssl, int type);
    }
}
