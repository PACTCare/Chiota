#region Directives
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// A Network utilities class
    /// </summary>
    public static class NetworkUtils
    {
        /// <summary>
        /// Determines the internet gateway address of this host
        /// </summary>
        /// 
        /// <param name="MaxHops">The maximum number of route hops to travel</param>
        /// 
        /// <returns>The gateway ip address, or <c>null</c> if the gateway could not be determined</returns>
        public static IPAddress GetGatewayAddress(int MaxHops = 2)
        {
            IPAddress[] list = GetLocalAddresses();

            // check for attached first
            for (int i = 0; i < list.Length; i++)
            {
                if (!IsPrivateIP(list[i]))
                    return list[i];
            }

            // try ipv6 first (google dns: 2001:4860:4860::8888 or 2001:4860:4860::8844)
            PingReply[] routev6 = TraceRoute(IPAddress.Parse("2001:4860:4860::8888"), MaxHops, 100);
            for (int i = 0; i < routev6.Length; i++)
            {
                if (!IsPrivateIP(routev6[i].Address))
                    return routev6[i].Address;
            }

            // now ipv4 (dns root-a 198.41.0.4)
            PingReply[] route = TraceRoute(new IPAddress(new byte[] { 198, 41, 0, 4 }), MaxHops, 100);
            for (int i = 0; i < route.Length; i++)
            {
                if (!IsPrivateIP(route[i].Address))
                    return route[i].Address;
            }

            return null;
        }

        /// <summary>
        /// Get the public IP address of this node.
        /// <para>Uses external servers to determine the public address of this node</para>
        /// </summary>
        /// 
        /// <param name="TimeOutMS">The number of milliseconds before the operation is cancelled; default is 10 seconds</param>
        /// 
        /// <returns>Returns the IP address or null on failure</returns>
        public static IPAddress GetPublicIpAddress(int TimeOutMS = 10000)
        {
            if (TimeOutMS < 10)
                throw new InvalidOperationException("NetworkUtils:GetPublicIpAddress: TimeOutMS must be at least 10 milliseconds!");

            IPAddress address = null;
            string ip = null;

            var request = (HttpWebRequest)WebRequest.Create("http://bot.whatismyipaddress.com/");
            request.Method = "GET";
            request.Timeout = TimeOutMS;

            try
            {
                using (WebResponse response = request.GetResponse())
                {
                    using (var reader = new System.IO.StreamReader(response.GetResponseStream()))
                        ip = reader.ReadToEnd().Trim();
                }
            }
            catch (WebException)
            {
            }

            // second try with alternate server
            if (string.IsNullOrEmpty(ip))
            {
                request = (HttpWebRequest)WebRequest.Create("http://ipecho.net/plain");

                try
                {
                    using (WebResponse response = request.GetResponse())
                    {
                        using (var reader = new System.IO.StreamReader(response.GetResponseStream()))
                            ip = reader.ReadToEnd().Trim();
                    }
                }
                catch (WebException)
                {
                }
            }

            if (IsValidIP(ip))
                IPAddress.TryParse(ip, out address);

            return address;
        }

        /// <summary>
        /// Determines if the remote host is reachable
        /// </summary>
        /// 
        /// <param name="Address">The ip address of the remote host</param>
        /// 
        /// <returns>Returns <c>true</c> if the host is reachable</returns>
        public static bool IsHostAlive(IPAddress Address)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send(Address);
                    return reply.Status == IPStatus.Success;
                }
            }
            catch (PingException)
            {
                return false;
            }
        }

        /// <summary>
        /// Checks to see if the address is owned by a local interface
        /// </summary>
        /// 
        /// <param name="Address">The IP address to check</param>
        /// 
        /// <returns>Returns <c>true</c> if the address is local</returns>
        public static bool IsLocalIP(IPAddress Address)
        {
            foreach (IPAddress ip in GetLocalAddresses())
            {
                if (Address.Equals(ip))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Test if an application is listening on a port
        /// </summary>
        /// 
        /// <param name="Port">The port to test</param>
        /// 
        /// <returns>Returns <c>true</c> if an application is listening on the port, otherwise <c>false</c></returns>
        /// 
        /// <exception cref="SocketException">Thrown if the operation is in an error state</exception>
        public static bool IsPortOpen(int Port)
        {
            var listener = default(TcpListener);

            try
            {
                listener = new TcpListener(IPAddress.Any, Port);
                listener.Start();

                return true;
            }
            catch (SocketException)
            {
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                if (listener != null)
                    listener.Stop();
            }

            return false;
        }

        /// <summary>
        /// Tests if an address is a private ip
        /// </summary>
        /// 
        /// <param name="Address">The ip address to test</param>
        /// 
        /// <returns>Returns <c>true</c> if the address is a private ip address, otherwise <c>false</c></returns>
        public static bool IsPrivateIP(IPAddress Address)
        {
            byte[] ip = Address.GetAddressBytes();

            if (ip[0] == 0)
                return true;

            if (Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return Address.IsIPv6LinkLocal || Address.IsIPv6SiteLocal;
            }
            else
            {
                return ((ip[0] == 10) || (ip[0] == 127) || (ip[0] > 223) ||
                    ((ip[0] == 192) && (ip[1] == 168)) ||
                    ((ip[0] == 172) && ((ip[1] & 0xf0) == 16)));
            }
        }

        /// <summary>
        /// Test string for valid ip address format
        /// </summary>
        /// 
        /// <param name="Ip">The ip address string</param>
        /// 
        /// <returns>Returns true if address is a valid format</returns>
        public static bool IsValidIP(IPAddress Ip)
        {
            byte[] addBytes = Ip.GetAddressBytes();

            switch (Ip.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    if (addBytes.Length == 4)
                        return true;
                    break;
                case AddressFamily.InterNetworkV6:
                    if (addBytes.Length == 16)
                        return true;
                    break;
                default:
                    break;
            }

            return false;
        }

        /// <summary>
        /// Test string for valid ip address format
        /// </summary>
        /// 
        /// <param name="Address">The ip address string</param>
        /// 
        /// <returns>Returns true if address is a valid format</returns>
        public static bool IsValidIP(string Address)
        {
            IPAddress ip;
            if (IPAddress.TryParse(Address, out ip))
            {
                switch (ip.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        if (Address.Length > 6 && Address.Contains("."))
                        {
                            string[] s = Address.Split('.');
                            if (s.Length == 4 && s[0].Length > 0 &&  s[1].Length > 0 &&  s[2].Length > 0 &&  s[3].Length > 0)
                                return true;
                        }
                        break;
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        if (Address.Contains(":") && Address.Length > 15)
                            return true;
                        break;
                    default:
                        break;
                }
            }

            return false;
        }

        /// <summary>
        /// Get the ip addresses associated with this host
        /// </summary>
        /// 
        /// <returns>An array of local ip addresses</returns>
        public static IPAddress[] GetLocalAddresses()
        {
            List<IPAddress> addresses = new List<IPAddress>();
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork || ip.Address.AddressFamily == AddressFamily.InterNetworkV6)
                            addresses.Add(ip.Address);
                    }
                }
            }

            return addresses.ToArray();
        }

        /// <summary>
        /// Get an open and randomly selected port number within a range
        /// </summary>
        /// 
        /// <param name="From">The minimum port number (default is 49152)</param>
        /// <param name="To">The maximum port number (default is 65535)</param>
        /// <returns>An open port number</returns>
        public static int NextOpenPort(int From = 49152, int To = 65535)
        {
            var rnd = new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPPrng();

            int port = -1;

            do
            {
                if (IsPortOpen((port = rnd.Next(From, To))))
                    break;

            } while (true);

            return port;
        }

        /// <summary>
        /// Parse the ip address from a string
        /// </summary>
        /// 
        /// <param name="Address">The ip address string</param>
        /// 
        /// <returns>Returns IPAddress or null on failure</returns>
        public static IPAddress Parse(string Address)
        {
            IPAddress ip;
            if (IPAddress.TryParse(Address, out ip))
                return ip;
            
            return null;
        }

        /// <summary>
        /// Resolve a host name to an ip address
        /// </summary>
        /// 
        /// <param name="HostName">The host name</param>
        /// 
        /// <returns>The hosts ip address or null if the name can not be resolved</returns>
        public static IPAddress Resolve(string HostName)
        {
            IPHostEntry host;
            IPAddress[] ipList;

            try
            {

                if (Uri.IsWellFormedUriString(HostName, UriKind.RelativeOrAbsolute) && Uri.CheckHostName(HostName) == UriHostNameType.Dns)
                {
                    // address of the host
                    host = Dns.GetHostEntry(HostName);
                    ipList = host.AddressList;
                    if (ipList == null || ipList.Length < 1)
                        return null;

                    return ipList[ipList.Length - 1];
                }
            }
            catch { }

            return null;
        }

        /// <summary>
        /// Performs a trace route on an ip address
        /// </summary>
        /// 
        /// <param name="Address">The target ip address</param>
        /// <param name="MaxHops">The maximum hopcount</param>
        /// <param name="PingTimeout">The timeout for each ping</param>
        /// 
        /// <returns>An array of PingReplys for the whole path</returns>
        public static PingReply[] TraceRoute(IPAddress Address, int MaxHops, int PingTimeout)
        {
            List<PingReply> replies = new List<PingReply>();
            Ping echo = new Ping();
            PingReply reply;

            for (int i = 1; i < MaxHops + 1; i++)
            {
                try
                {
                    reply = echo.Send(Address, PingTimeout, new byte[10], new PingOptions(i, false));
                    if (reply.Status == IPStatus.Success)
                        i = MaxHops;

                    replies.Add(reply);
                }
                catch (PingException)
                {
                    continue;
                }
            }

            return replies.ToArray();
        }
    }
}
