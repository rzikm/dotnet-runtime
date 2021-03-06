// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Net.Quic.Implementations.Managed.Internal.Tls.OpenSsl;
using System.Net.Security;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static unsafe class OpenSslQuic
    {
        internal const int CRYPTO_EX_INDEX_SSL = 0;
        internal const int SSL_TLSEXT_ERR_NOACK = 3;
        internal const int SSL_TLSEXT_ERR_OK = 0;

        internal const string Ssl = Libraries.Ssl;
        internal const string Crypto = Libraries.Crypto;

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

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "TLS_method")]
        internal static extern IntPtr TlsMethod();

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "CRYPTO_get_ex_new_index")]
        internal static extern int CryptoGetExNewIndex(int classIndex, long argl, IntPtr argp, IntPtr newFunc,
            IntPtr dupFunc, IntPtr freeFunc);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int ErrorPrintCallback(byte* str, UIntPtr len, IntPtr u);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_new")]
        internal static extern IntPtr SslCtxNew(IntPtr method);


        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_free")]
        internal static extern void SslCtxFree(IntPtr ctx);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_set_client_cert_cb")]
        internal static extern IntPtr SslCtxSetClientCertCb(IntPtr method);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_new")]
        internal static extern IntPtr SslNew(IntPtr ctx);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_free")]
        internal static extern void SslFree(IntPtr ssl);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_use_certificate_file")]
        internal static extern int SslUseCertificateFile(IntPtr ssl, [MarshalAs(UnmanagedType.LPStr
            )]
            string file, SslFiletype type);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_use_PrivateKey_file")]
        internal static extern int SslUsePrivateKeyFile(IntPtr ssl, [MarshalAs(UnmanagedType.LPStr
            )]
            string file, SslFiletype type);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_use_cert_and_key")]
        internal static extern int SslUseCertAndKey(IntPtr ssl, IntPtr x509, IntPtr privateKey, IntPtr caChain, int doOverride);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_use_certificate")]
        internal static extern int SslUseCertificate(IntPtr ssl, IntPtr x509);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_version")]
        internal static extern byte* SslGetVersion(IntPtr ssl);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_quic_method")]
        internal static extern int SslSetQuicMethod(IntPtr ssl, IntPtr methods);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_accept_state")]
        internal static extern int SslSetAcceptState(IntPtr ssl);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_connect_state")]
        internal static extern int SslSetConnectState(IntPtr ssl);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_do_handshake")]
        internal static extern int SslDoHandshake(IntPtr ssl);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_ctrl")]
        internal static extern int SslCtrl(IntPtr ssl, SslCtrlCommand cmd, long larg, IntPtr parg);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_callback_ctrl")]
        internal static extern int SslCallbackCtrl(IntPtr ssl, SslCtrlCommand cmd, IntPtr fp);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_callback_ctrl")]
        internal static extern int SslCtxCallbackCtrl(IntPtr ctx, SslCtrlCommand cmd, IntPtr fp);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_error")]
        internal static extern int SslGetError(IntPtr ssl, int code);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_provide_quic_data")]
        internal static extern int SslProvideQuicData(IntPtr ssl, OpenSslEncryptionLevel level, byte* data, IntPtr len);

        internal static int SslProvideQuicData(IntPtr ssl, OpenSslEncryptionLevel level, ReadOnlySpan<byte> data)
        {
            fixed (byte* pData = data)
            {
                return SslProvideQuicData(ssl, level, pData, new IntPtr(data.Length));
            }
        }

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_ex_data")]
        internal static extern int SslSetExData(IntPtr ssl, int idx, IntPtr data);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_ex_data")]
        internal static extern IntPtr SslGetExData(IntPtr ssl, int idx);

        internal static int SslSetTlsExtHostName(IntPtr ssl, string hostname)
        {
            var addr = Marshal.StringToHGlobalAnsi(hostname);
            const long TLSEXT_NAMETYPE_host_name = 0;
            int res = SslCtrl(ssl, SslCtrlCommand.SetTlsextHostname, TLSEXT_NAMETYPE_host_name, addr);
            Marshal.FreeHGlobal(addr);
            return res;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int TlsExtServernameCallback(IntPtr ssl, ref int al, IntPtr arg);

        internal static int SslCtxSetTlsExtServernameCallback(IntPtr ctx, TlsExtServernameCallback callback)
        {
            var addr = Marshal.GetFunctionPointerForDelegate(callback);
            return SslCtxCallbackCtrl(ctx, SslCtrlCommand.SetTlsextServernameCb, addr);
        }

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_quic_transport_params")]
        internal static extern int SslSetQuicTransportParams(IntPtr ssl, byte* param, IntPtr length);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_peer_quic_transport_params")]
        internal static extern int SslGetPeerQuicTransportParams(IntPtr ssl, out byte* param, out IntPtr length);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_quic_write_level")]
        internal static extern OpenSslEncryptionLevel SslQuicWriteLevel(IntPtr ssl);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_is_init_finished")]
        internal static extern int SslIsInitFinished(IntPtr ssl);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_current_cipher")]
        internal static extern IntPtr SslGetCurrentCipher(IntPtr ssl);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CIPHER_get_protocol_id")]
        internal static extern ushort SslCipherGetProtocolId(IntPtr cipher);

        internal static TlsCipherSuite SslGetCipherId(IntPtr ssl)
        {
            var cipher = SslGetCurrentCipher(ssl);
            return (TlsCipherSuite)SslCipherGetProtocolId(cipher);
        }

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_ciphersuites")]
        internal static extern int SslSetCiphersuites(IntPtr ssl, byte* list);

        internal static int SslSetCiphersuites(IntPtr ssl, string list)
        {
            var ptr = Marshal.StringToHGlobalAnsi(list);
            int result = SslSetCiphersuites(ssl, (byte*)ptr.ToPointer());
            Marshal.FreeHGlobal(ptr);
            return result;
        }

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_cipher_list")]
        internal static extern int SslSetCipherList(IntPtr ssl, byte* list);

        internal static int SslSetCipherList(IntPtr ssl, string list)
        {
            var ptr = Marshal.StringToHGlobalAnsi(list);
            int result = SslSetCipherList(ssl, (byte*)ptr.ToPointer());
            Marshal.FreeHGlobal(ptr);
            return result;
        }

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_cipher_list")]
        internal static extern IntPtr SslGetCipherList(IntPtr ssl, int priority);

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

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_set_alpn_protos")]
        internal static extern int SslSetAlpnProtos(IntPtr ssl, IntPtr protosStr, int protosLen);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get0_alpn_selected")]
        internal static extern int SslGet0AlpnSelected(IntPtr ssl, out IntPtr data, out int len);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_CTX_set_alpn_select_cb")]
        internal static extern int SslCtxSetAlpnSelectCb(IntPtr ctx, IntPtr cb, IntPtr arg);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int AlpnSelectCb(IntPtr ssl, ref byte* pOut, ref byte outLen, byte* pIn, int inLen, IntPtr arg);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_peer_certificate")]
        internal static extern IntPtr SslGetPeerCertificate(IntPtr ssl);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_s_mem")]
        internal static extern IntPtr BioSMem();

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_new")]
        internal static extern IntPtr BioNew(IntPtr bioMethod);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_new_mem_buf")]
        internal static extern IntPtr BioNewMemBuf(byte* buf, int len);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_free")]
        internal static extern void BioFree(IntPtr bio);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "BIO_write")]
        internal static extern int BioWrite(IntPtr bio, byte* data, int dlen);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "PEM_read_bio_X509")]
        internal static extern IntPtr PemReadBioX509(IntPtr bio, IntPtr pOut, IntPtr pemPasswordCb, IntPtr u);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "d2i_X509")]
        internal static extern IntPtr D2iX509(IntPtr pOut, ref byte* data, int len);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "d2i_PKCS12_bio")]
        internal static extern IntPtr D2iPkcs12(IntPtr pOut, ref byte* data, int len);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "PKCS12_parse")]
        internal static extern int Pkcs12Parse(IntPtr pkcs, IntPtr pass, out IntPtr key, out IntPtr cert, out IntPtr caStack);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "PKCS12_free")]
        internal static extern void Pkcs12Free(IntPtr pkcs);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "X509_free")]
        internal static extern void X509Free(IntPtr x509);

        [DllImport(Crypto, EntryPoint = EntryPointPrefix + "EVP_PKEY_free")]
        internal static extern void EvpPKeyFree(IntPtr evpKey);

        // [DllImport(Libraries.Crypto, EntryPoint = LibPrefix + "OPENSSL_sk_kj")]
        // internal static extern void SkX509Free(IntPtr stack);

        [DllImport(Ssl, EntryPoint = EntryPointPrefix + "SSL_get_servername")]
        internal static extern IntPtr SslGetServername(IntPtr ssl, int type);
    }
}
