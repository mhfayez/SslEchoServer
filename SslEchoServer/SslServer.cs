using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
/**
 * Author: Mohammad Homayoon Fayez
 * Zealand - Akademy of Technologies and Business
 * Date: April 2022
 * Copyright 2022 Mohammad Homayoon Fayez (mofa@zealand.dk)
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 **/
namespace SslEchoServer
{
    class SslServer
    {
        private int _port;
        private IPAddress _serverAddress;
        private TcpListener _serverSocket;
        private TcpClient _connectionSocket;
        private Stream _unsecureStream;
        private string _serverCertificateFile;
        private string _serverCertificateFilePassword;
        private bool _clientCertificateRequired = false;
        private bool _checkCertificateRevocation = false;
        private bool _leaveInnerStreamOpen = false;
        private bool _validateClient;
        private SslStream _sslStream;
        private SslProtocols _enabledSSLProtocols;
        private RemoteCertificateValidationCallback _remoteCertificateValidationCallback;
        private LocalCertificateSelectionCallback _localCertificateSelectionCallback;

        public SslServer(IPAddress serverAddress, int port, string serverCertificateFile, string serverCertificateFilePassword)
        {
            _port = port;
            _serverAddress = serverAddress;
            _serverCertificateFile = serverCertificateFile;
            _serverCertificateFilePassword = serverCertificateFilePassword;

        }
        
        public bool AcceptClient()
        {
            _serverSocket = new TcpListener(_serverAddress, _port);
            _serverSocket.Start();
            Console.WriteLine("Server listening for incomming connection request");

            _connectionSocket = _serverSocket.AcceptTcpClient();
            Console.WriteLine("Client Connecte");

            _unsecureStream = _connectionSocket.GetStream();

            return true;
        }

        public bool AuthenticateAsServer()
        {
            X509Certificate serverCertificate = new X509Certificate2(_serverCertificateFile, _serverCertificateFilePassword);
            _sslStream = new SslStream(_unsecureStream, _leaveInnerStreamOpen, _remoteCertificateValidationCallback, _localCertificateSelectionCallback);
            _enabledSSLProtocols = SslProtocols.Tls;
            _sslStream.AuthenticateAsServer(serverCertificate, _clientCertificateRequired, _enabledSSLProtocols, _checkCertificateRevocation);
            Console.WriteLine("Server authenticated");

            DisplayCertificateInfoAndSecurity();

            return true;
        }

        public void Talk()
        {
            StreamReader sr = new StreamReader(_sslStream);
            StreamWriter sw = new StreamWriter(_sslStream);
            sw.AutoFlush = true; // enable automatic flushing

            string message = sr.ReadLine();

            string answer;

            while (message != null && message != "")
            {
                Console.WriteLine("Client: " + message);
                answer = message.ToUpper();
                sw.WriteLine(answer);
                message = sr.ReadLine();
            }

            _sslStream.Close();
            _connectionSocket.Close();
            _serverSocket.Stop();
        }

        private void DisplayCertificateInfoAndSecurity()
        {
            Console.WriteLine("---------------------- Security Services -------------------------");
            Console.WriteLine("Is authenticated: {0} as server? {1}", _sslStream.IsAuthenticated, _sslStream.IsServer);
            Console.WriteLine("IsSigned: {0}", _sslStream.IsSigned);
            Console.WriteLine("Is Encrypted: {0}", _sslStream.IsEncrypted);

            Console.WriteLine("---------------------- Security Level -------------------------");
            Console.WriteLine("Cipher: {0} strength {1}", _sslStream.CipherAlgorithm, _sslStream.CipherStrength);
            Console.WriteLine("Hash: {0} strength {1}", _sslStream.HashAlgorithm, _sslStream.HashStrength);
            Console.WriteLine("Key exchange: {0} strength {1}", _sslStream.KeyExchangeAlgorithm, _sslStream.KeyExchangeStrength);
            Console.WriteLine("Protocol: {0}", _sslStream.SslProtocol);

            DisplayCertificateInformation();
        }

        private void DisplayCertificateInformation()
        {
            Console.WriteLine("Certificate revocation list checked: {0}", _sslStream.CheckCertRevocationStatus);

            X509Certificate localCertificate = _sslStream.LocalCertificate;
            if (_sslStream.LocalCertificate != null)
            {
                Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Local certificate is null.");
            }
            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = _sslStream.RemoteCertificate;
            if (_sslStream.RemoteCertificate != null)
            {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }

    }
}
