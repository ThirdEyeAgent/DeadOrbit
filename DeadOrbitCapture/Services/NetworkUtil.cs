using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DeadOrbitCapture.Services
{
    public static class NetworkUtil
    {
        public static IPAddress GetLocalIPv4()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.OperationalStatus == OperationalStatus.Up
                                  && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
            {
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork
                        && !IPAddress.IsLoopback(ua.Address)
                        && !ua.Address.ToString().StartsWith("169.254"))
                    {
                        return ua.Address;
                    }
                }
            }

            var host = Dns.GetHostName();
            var entry = Dns.GetHostEntry(host);
            return entry.AddressList
                        .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork
                                          && !a.ToString().StartsWith("169.254"))
                   ?? IPAddress.Loopback;
        }
    }
}
