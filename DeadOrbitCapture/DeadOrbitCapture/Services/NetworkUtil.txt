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
            // Prefer active, non-loopback IPv4; ignore APIPA 169.254.x.x
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var props = ni.GetIPProperties();
                foreach (var ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(ua.Address))
                    {
                        var s = ua.Address.ToString();
                        if (!s.StartsWith("169.254")) // skip APIPA
                            return ua.Address;
                    }
                }
            }

            // Fallback: try DNS
            var host = Dns.GetHostName();
            var entry = Dns.GetHostEntry(host);
            var ipv4 = entry.AddressList.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork &&
                                                             !a.ToString().StartsWith("169.254"));
            return ipv4 ?? IPAddress.Loopback;
        }
    }
}
