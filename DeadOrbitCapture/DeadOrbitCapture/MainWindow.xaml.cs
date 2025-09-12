using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Windows;
using DeadOrbitCapture.Models;
using DeadOrbitCapture.Services;

namespace DeadOrbitCapture
{
    public partial class MainWindow : Window
    {
        private DnsServer? _dns;
        private HttpCaptureService? _http;
        private readonly FileLogger _fileLogger = new();
        public ObservableCollection<RequestLogEntry> Entries { get; } = new();

        public MainWindow()
        {
            InitializeComponent();
            LogList.ItemsSource = Entries;
        }

        private void Start_Click(object sender, RoutedEventArgs e)
        {
            Entries.Clear();

            _dns?.Stop();
            _dns = new DnsServer(LogFromService);
            _dns.Start();
            var ip = _dns.GetAdvertisedIPv4();

            _http?.Stop();
            var strategy = GetSelectedSignatureStrategy();
            _http = new HttpCaptureService(80, OnRequestReceived, LogFromService, strategy);
            _http.Start();

            Title = $"DeadOrbit Capture — DNS: {ip} — HTTP: 80 — LOOSE+STRUCTURE — SIG={strategy}";
            IpText.Text = $"Local IPv4: {ip}  |  Set this as DNS in RPCS3";
            LogFromService($"[INFO] Services started in LOOSE+STRUCTURE MODE (Signature={strategy}). Advertising {ip} for target domains; listening on HTTP :80");

            Directory.CreateDirectory(_fileLogger.LogDirectory);
        }

        private void Stop_Click(object sender, RoutedEventArgs e)
        {
            _dns?.Stop();
            _http?.Stop();
            LogFromService("[INFO] Services stopped.");
        }

        private void ExportLog_Click(object sender, RoutedEventArgs e)
        {
            var strategy = GetSelectedSignatureStrategy();
            var fileName = $"SessionLog_LOOSE_SIG-{strategy}_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.txt";
            var path = Path.Combine(_fileLogger.LogDirectory, fileName);

            using var sw = new StreamWriter(path);
            foreach (var entry in Entries)
            {
                sw.WriteLine($"[{entry.Timestamp:O}] {entry.Display}");
                if (!string.IsNullOrWhiteSpace(entry.Headers))
                    sw.WriteLine("Headers:\n" + entry.Headers);
                if (!string.IsNullOrWhiteSpace(entry.Body))
                    sw.WriteLine("Body:\n" + entry.Body);
                if (!string.IsNullOrWhiteSpace(entry.ResponseBody))
                    sw.WriteLine("Response:\n" + entry.ResponseBody);
                sw.WriteLine();
            }

            LogFromService($"[INFO] Log exported to {path}");

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{path}\"",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                LogFromService($"[ERROR] Could not open file location: {ex.Message}");
            }
        }

        private void ShowIfaces_Click(object sender, RoutedEventArgs e)
        {
            LogFromService("[INFO] Interface dump start");
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                LogFromService($"IF: {ni.Name} | {ni.Description} | {ni.NetworkInterfaceType} | {ni.OperationalStatus}");
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    LogFromService($"  - {ua.Address.AddressFamily} {ua.Address}");
                }
            }
            LogFromService("[INFO] Interface dump end");
        }

        private void OnRequestReceived(RequestLogEntry entry)
        {
            var path = _fileLogger.Save(entry);
            entry.FilePath = path;
            entry.Display = $"[{entry.Timestamp:HH:mm:ss}] HTTP {entry.Method} {entry.Url} ({entry.StatusCode})";
            Dispatcher.Invoke(() => Entries.Add(entry));
        }

        private void LogFromService(string message)
        {
            var entry = new RequestLogEntry
            {
                Timestamp = DateTime.Now,
                Method = "INFO",
                Url = message,
                Display = message
            };
            Dispatcher.Invoke(() => Entries.Add(entry));
        }

        private SignatureStrategy GetSelectedSignatureStrategy()
        {
            try
            {
                var item = SignatureModeBox.SelectedItem as System.Windows.Controls.ComboBoxItem;
                var text = (item?.Content as string)?.Trim() ?? "Zero";
                return text switch
                {
                    "Echo" => SignatureStrategy.Echo,
                    "Random" => SignatureStrategy.Random,
                    _ => SignatureStrategy.Zero
                };
            }
            catch
            {
                return SignatureStrategy.Zero;
            }
        }
    }
}
