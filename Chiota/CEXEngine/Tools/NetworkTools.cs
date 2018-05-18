#region Directives
using System.Collections;
using System.Net;
using System.Net.NetworkInformation;
#endregion

namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// A networking tools class
    /// </summary>
    public static class NetworkTools
    {
        /// <summary>
        /// Tests if an address is a private ip
        /// </summary>
        /// 
        /// <param name="Address">The ip address to test</param>
        /// 
        /// <returns>Returns <c>true</c> if the address is a private ip address, otherwise <c>false</c></returns>
        public static bool IsPrivateAddress(IPAddress Address)
        {
            if (Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                return Address.IsIPv6LinkLocal || Address.IsIPv6SiteLocal;
            
            byte[] bytes = Address.GetAddressBytes();

            return ((bytes[0] == 10) ||
                ((bytes[0] == 192) && (bytes[1] == 168)) ||
                ((bytes[0] == 172) && ((bytes[1] & 0xF0) == 16)));
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
            ArrayList replies = new ArrayList();
            Ping echo = new Ping();
            PingReply reply;

            for (int i = 1; i < MaxHops; i++)
            {
                reply = echo.Send(Address, PingTimeout, new byte[10], new PingOptions(i, false));
                if (reply.Status == IPStatus.Success)
                    i = MaxHops;
                
                replies.Add(reply);
            }

            PingReply[] pingReplies = new PingReply[replies.Count];

            for (int i = 0; i < replies.Count; i++)
                pingReplies[i] = (PingReply)replies[i];
            
            return pingReplies;
        }
    }
}
