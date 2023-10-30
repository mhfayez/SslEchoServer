using System;
using System.Net;

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
    class Program
    {
        private static int _port = 6789;
        private static IPAddress _serverAddress = IPAddress.Loopback;
        private static SslServer _sslserver;
        private static bool _clientConnected;
        private static bool _authenticated;
        private static string _serverCertificateFile = "C:/certificate2/echoServerContainer.pfx";
        private static string _serverCertificateFilePassword = "";



        public static void Main(string[] args)
        {
            //creates an instance of SSLServer on localhost port _port
            _sslserver = new SslServer(_serverAddress, _port, _serverCertificateFile, _serverCertificateFilePassword);

            //Accepts the client connection request on localhost port 6789
            _clientConnected = _sslserver.AcceptClient();

            if(_clientConnected)
            {
               _authenticated =  _sslserver.AuthenticateAsServer();
            }

            if (_authenticated)
            {
                _sslserver.Talk();
            }

        }
    }
}
