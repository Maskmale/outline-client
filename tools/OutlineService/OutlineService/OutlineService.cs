// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using Newtonsoft.Json;

/*
 * Windows Service, part of the Outline Windows client, to configure routing.
 * Modifying the system routes requires admin permissions, so this service must be installed
 * and started as admin.
 *
 * The service listens on a named pipe and supports the following JSON API:
 *
 * Requests
 *
 * configureRouting: Modifies the system's routing table to route all traffic through the TAP device
 * except that destined for proxyIp. Disables IPv6 traffic.
 *    { action: "configureRouting", parameters: {"proxyIp": <IPv4 address>, "isAutoConnect": "false" }}
 *
 *  resetRouting: Restores the system's default routing.
 *    { action: "resetRouting"}
 *
 * Response
 *
 *  { statusCode: <int>, action: <string> errorMessage?: <string> }
 *  
 *  The service will send connection status updates if the pipe connection is kept
 *  open by the client. Such responses have the form:
 *  
 *  { statusCode: <int>, action: "statusChanged", connectionStatus: <int> }
 *
 */
namespace OutlineService
{
    public partial class OutlineService : ServiceBase
    {
        private const string EVENT_LOG_SOURCE = "OutlineService";
        private const string EVENT_LOG_NAME = "Application";
        // Must be kept in sync with the Electron code.
        private const string PIPE_NAME = "OutlineServicePipe";
        private const string TAP_DEVICE_NAME = "outline-tap0";
        private const string TAP_DEVICE_IP = "10.0.85.1";

        private const string ACTION_CONFIGURE_ROUTING = "configureRouting";
        private const string ACTION_RESET_ROUTING = "resetRouting";
        private const string ACTION_STATUS_CHANGED = "statusChanged";
        private const string PARAM_PROXY_IP = "proxyIp";
        private const string PARAM_AUTO_CONNECT = "isAutoConnect";

        private static string[] IPV4_SUBNETS = { "0.0.0.0/1", "128.0.0.0/1" };
        private static string[] IPV6_SUBNETS = { "fc00::/7", "2000::/4", "3000::/4" };
        private static string[] IPV4_RESERVED_SUBNETS = {
            "172.16.0.0/12",
        };
        private const string CMD_NETSH = "netsh";

        private const uint BUFFER_SIZE_BYTES = 1024;

        private EventLog eventLog;
        private NamedPipeServerStream pipe;
        private string proxyIp;
        private string gatewayIp;
        private int gatewayInterfaceIndex;

        // Time, in ms, to wait until considering smartdnsblock.exe to have successfully launched.
        private const int SMART_DNS_BLOCK_TIMEOUT_MS = 1000;

        // Do as little as possible here because any error thrown will cause "net start" to fail
        // without anything being added to the application log.
        public OutlineService()
        {
            InitializeComponent();

            eventLog = new EventLog();
            if (!EventLog.SourceExists(EVENT_LOG_SOURCE))
            {
                EventLog.CreateEventSource(EVENT_LOG_SOURCE, EVENT_LOG_NAME);
            }
            eventLog.Source = EVENT_LOG_SOURCE;
            eventLog.Log = EVENT_LOG_NAME;
        }

        protected override void OnStart(string[] args)
        {
            eventLog.WriteEntry("OutlineService starting");
            NetworkChange.NetworkAddressChanged +=
                new NetworkAddressChangedEventHandler(NetworkAddressChanged);
            CreatePipe();
        }

        protected override void OnStop()
        {
            eventLog.WriteEntry("OutlineService stopping");
            DestroyPipe();
            NetworkChange.NetworkAddressChanged -= NetworkAddressChanged;
        }

        private void CreatePipe()
        {
            var pipeSecurity = new PipeSecurity();
            pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(
                WellKnownSidType.CreatorOwnerSid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
            pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(
                WellKnownSidType.AuthenticatedUserSid, null),
                PipeAccessRights.ReadWrite, AccessControlType.Allow));

            pipe = new NamedPipeServerStream(PIPE_NAME, PipeDirection.InOut, -1, PipeTransmissionMode.Message,
                                             PipeOptions.Asynchronous, (int)BUFFER_SIZE_BYTES, (int)BUFFER_SIZE_BYTES, pipeSecurity);
            pipe.BeginWaitForConnection(HandleConnection, null);
        }

        private void DestroyPipe()
        {
            if (pipe == null)
            {
                return;
            }
            try
            {
                if (pipe.IsConnected)
                {
                    pipe.Disconnect();
                }
                pipe.Close();
                pipe = null;
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"Got an exception while destroying the pipe: {e.ToString()}",
                                    EventLogEntryType.Warning);
            }
        }

        private void HandleConnection(IAsyncResult result)
        {
            eventLog.WriteEntry("Got incoming connection");

            // Save the network config before we do anything. If the request fails
            // it will be sent to the client for inclusion in Sentry reports.
            var beforeNetworkInfo = GetNetworkInfo();

            try
            {
                pipe.EndWaitForConnection(result);
                // Keep the pipe connected to send connection status updates.
                while (pipe.IsConnected)
                {
                    ServiceResponse response = new ServiceResponse();
                    var request = ReadRequest();
                    if (request == null)
                    {
                        response.statusCode = (int)ErrorCode.GenericFailure;
                    }
                    else
                    {
                        response.action = request.action;
                        try
                        {
                            HandleRequest(request);
                        }
                        catch (Exception e)
                        {
                            response.statusCode = (int)ErrorCode.GenericFailure;
                            response.errorMessage = $"{e.Message} (network config: {beforeNetworkInfo})";
                            eventLog.WriteEntry($"request failed: {e.Message}", EventLogEntryType.Error);
                        }
                    }
                    WriteResponse(response);
                }
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"Failed to handle connection: {e.ToString()}", EventLogEntryType.Error);
            }
            finally
            {
                // Pipe streams are one-to-one connections. Recreate the pipe to handle subsequent requests.
                DestroyPipe();
                CreatePipe();
            }
        }

        private ServiceRequest ReadRequest()
        {
            var stringBuilder = new StringBuilder();
            var buffer = new byte[BUFFER_SIZE_BYTES];
            var memoryStream = new MemoryStream();
            do
            {
                var readBytes = pipe.Read(buffer, 0, buffer.Length);
                memoryStream.Write(buffer, 0, readBytes);
            } while (!pipe.IsMessageComplete);
            var msg = Encoding.UTF8.GetString(buffer);
            if (String.IsNullOrWhiteSpace(msg))
            {
                eventLog.WriteEntry("Failed to read request", EventLogEntryType.Error);
                return null;
            }
            eventLog.WriteEntry($"message from client: {msg}");
            return ParseRequest(msg);
        }

        private ServiceRequest ParseRequest(string jsonRequest)
        {
            try
            {
                return JsonConvert.DeserializeObject<ServiceRequest>(jsonRequest);
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"Failed to parse request: {e.ToString()}");
            }
            return null;
        }

        private void WriteResponse(ServiceResponse response)
        {
            var jsonResponse = SerializeResponse(response);
            if (jsonResponse == null)
            {
                eventLog.WriteEntry("Failed to serialize response.", EventLogEntryType.Error);
                return;
            }
            eventLog.WriteEntry($"message to client: {jsonResponse}");
            var jsonResponseBytes = Encoding.UTF8.GetBytes(jsonResponse);
            pipe.Write(jsonResponseBytes, 0, jsonResponseBytes.Length);
            pipe.Flush();
            pipe.WaitForPipeDrain();
        }

        private string SerializeResponse(ServiceResponse response)
        {
            try
            {
                return JsonConvert.SerializeObject(response);
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"Failed to serialize response: {e.ToString()}");
            }
            return null;
        }

        private void HandleRequest(ServiceRequest request)
        {
            switch (request.action)
            {
                case ACTION_CONFIGURE_ROUTING:
                    ConfigureRouting(request.parameters[PARAM_PROXY_IP], Boolean.Parse(request.parameters[PARAM_AUTO_CONNECT]));
                    break;
                case ACTION_RESET_ROUTING:
                    ResetRouting(proxyIp, gatewayInterfaceIndex);
                    break;
                default:
                    eventLog.WriteEntry($"Received invalid request: {request.action}", EventLogEntryType.Error);
                    break;
            }
        }

        // Routes all traffic except that destined for the proxy server through the TUN device,
        // creating the illusion of a system-wide VPN.
        //
        // The key steps are:
        //  - Redirect all IPv4 traffic through the TAP device.
        //  - Find a gateway (actually a complex process, see #xxx).
        //  - Create a route to the proxy server via the gateway.
        //  - Bypass LAN addresses, by creating several routes via the gateway.
        //
        // Note:
        //  - Currently, we do not "clean up" in the event of failure. Instead, we reply on the
        //    client to call ResetRouting following a failure.
        //  - If autostart is true and a gateway cannot be found then an exception will *not* be
        //    thrown. Since the IPv4 redirect will remain in place, this all serves to prevent
        //    leaking traffic.
        //  - A couple of additional steps, viz. disabling "Smart DNS" and blocking IPv6  traffic,
        //    don't change the basic technique of "redirect all traffic except to the proxy".
        //
        // TODO: The client needs to handle certain autoconnect failures better, e.g. if IPv4
        //       redirect fails then we're not just reconnecting: we're leaking traffic.
        public void ConfigureRouting(string proxyIp, bool isAutoConnect)
        {
            try
            {
                StartSmartDnsBlock();
                eventLog.WriteEntry($"started smartdnsblock");
            }
            catch (Exception e)
            {
                throw new Exception($"could not start smartdnsblock: {e.Message}");
            }

            try
            {
                AddIpv4Redirect();
                eventLog.WriteEntry($"redirected IPv4 traffic");
            }
            catch (Exception e)
            {
                throw new Exception($"could not redirect IPv4 traffic: {e.Message}");
            }

            try
            {
                StopRoutingIpv6();
                eventLog.WriteEntry($"blocked IPv6 traffic");
            }
            catch (Exception e)
            {
                throw new Exception($"could not block IPv6 traffic: {e.Message}");
            }

            try
            {
                GetSystemIpv4Gateway(proxyIp);

                eventLog.WriteEntry($"connecting via gateway at {gatewayIp} on interface {gatewayInterfaceIndex}");

                // TODO: See the above TODO on handling these failures better during auto-connect.
                try
                {
                    AddProxyRoute(proxyIp, gatewayIp, gatewayInterfaceIndex);
                    eventLog.WriteEntry($"created route to proxy");
                }
                catch (Exception e)
                {
                    throw new Exception($"could not create route to proxy: {e.Message}");
                }

                try
                {
                    AddReservedSubnetBypass(gatewayIp, gatewayInterfaceIndex);
                    eventLog.WriteEntry($"created LAN bypass routes");
                }
                catch (Exception e)
                {
                    throw new Exception($"could not create LAN bypass routes: {e.Message}");
                }
            }
            catch (Exception e) when (isAutoConnect)
            {
                eventLog.WriteEntry($"could not reconnect during auto-connect: {e.Message}", EventLogEntryType.Warning);
            }

            this.proxyIp = proxyIp;
        }

        // Resets the routing table as much as possible, viz.:
        //  - Remove our IPv4 redirect.
        //  - Unblock IPv6.
        //  - Delete the explicit route to the proxy server, if we know the proxy server's IP.
        //  - Delete the LAN bypass routes.
        //  - Stop Smart DNS block.
        //
        // Notes:
        //  - Always tries to lift IPv4 blocks, etc., in case the service was restarted.
        //  - Basically never throws an exception.
        public void ResetRouting(string proxyIp, int gatewayInterfaceIndex)
        {
            try
            {
                RemoveIpv4Redirect();
                eventLog.WriteEntry($"removed IPv4 redirect");
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"failed to remove IPv4 redirect during disconnect: {e.Message}", EventLogEntryType.Error);
            }

            try
            {
                StartRoutingIpv6();
                eventLog.WriteEntry($"unblocked IPv6");
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"failed to unblock IPv6 during disconnect: {e.Message}", EventLogEntryType.Error);
            }

            // TODO: should we lookup the gateway interface?
            if (proxyIp != null)
            {
                try
                {
                    DeleteProxyRoute(proxyIp, gatewayInterfaceIndex);
                    eventLog.WriteEntry($"deleted route to proxy");
                }
                catch (Exception e)
                {
                    eventLog.WriteEntry($"failed to delete route to proxy during disconnect: {e.Message}",
                        EventLogEntryType.Error);
                }

                this.proxyIp = null;

                try
                {
                    RemoveReservedSubnetBypass(gatewayInterfaceIndex);
                    eventLog.WriteEntry($"deleted LAN bypass routes");
                }
                catch (Exception e)
                {
                    eventLog.WriteEntry($"failed to delete LAN bypass routes during disconnect: {e.Message}",
                        EventLogEntryType.Error);
                }
            }
            else
            {
                eventLog.WriteEntry("do not know proxy address, cannot delete route during disconnect", EventLogEntryType.Warning);
            }

            try
            {
                StopSmartDnsBlock();
                eventLog.WriteEntry($"stopped smartdnsblock");
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"failed to stop smartdnsblock during disconnect: {e.Message}",
                    EventLogEntryType.Warning);
            }
        }

        // Disable "Smart Multi-Homed Name Resolution", to ensure the system uses only the
        // (non-filtered) DNS server(s) associated with the TAP device.
        //
        // Notes:
        //  - To show the current firewall rules:
        //      netsh wfp show filters
        //  - This website is an easy way to quickly verify there are no DNS leaks:
        //      https://ipleak.net/
        //  - Because .Net provides *no way* to associate the new process with this one, the
        //    new process will continue to run even if this service is interrupted or crashes.
        //    Fortunately, since the changes it makes are *not* persistent, the system can, in
        //    the worst case, be fixed by rebooting.
        private void StartSmartDnsBlock()
        {
            // smartdnsblock.exe must be a sibling of OutlineService.exe.
            Process smartDnsBlock = new Process();
            smartDnsBlock.StartInfo.FileName = new DirectoryInfo(Process.GetCurrentProcess().MainModule.FileName).Parent.FullName +
                Path.DirectorySeparatorChar + "smartdnsblock.exe";
            smartDnsBlock.StartInfo.UseShellExecute = false;

            smartDnsBlock.StartInfo.RedirectStandardError = true;
            smartDnsBlock.StartInfo.RedirectStandardOutput = true;

            // This is for Windows 7: without it, the process exits immediately, presumably
            // because stdin isn't connected to anything:
            //   https://github.com/Jigsaw-Code/outline-client/issues/415
            //
            // This seems to make no difference on Windows 8 and 10.
            smartDnsBlock.StartInfo.RedirectStandardInput = true;

            ArrayList stdout = new ArrayList();
            ArrayList stderr = new ArrayList();
            smartDnsBlock.OutputDataReceived += (object sender, DataReceivedEventArgs e) =>
            {
                if (!String.IsNullOrEmpty(e.Data))
                {
                    stdout.Add(e.Data);
                }
            };
            smartDnsBlock.ErrorDataReceived += (object sender, DataReceivedEventArgs e) =>
            {
                if (!String.IsNullOrEmpty(e.Data))
                {
                    stderr.Add(e.Data);
                }
            };

            try
            {
                smartDnsBlock.Start();
                smartDnsBlock.BeginOutputReadLine();
                smartDnsBlock.BeginErrorReadLine();
            }
            catch (Exception e)
            {
                throw new Exception($"could not launch smartdnsblock at {smartDnsBlock.StartInfo.FileName}: { e.Message}");
            }

            // This does *not* throw if the process is still running after Nms.
            smartDnsBlock.WaitForExit(SMART_DNS_BLOCK_TIMEOUT_MS);
            if (smartDnsBlock.HasExited)
            {
                throw new Exception($"smartdnsblock failed " + $"(stdout: {String.Join(Environment.NewLine, stdout.ToArray())}, " +
                    $"(stderr: {String.Join(Environment.NewLine, stderr.ToArray())})");
            }
        }

        private void StopSmartDnsBlock()
        {
            try
            {
                RunCommand("powershell", "stop-process -name smartdnsblock");
            }
            catch (Exception e)
            {
                throw new Exception($"could not kill smartdnsblock: {e.Message}");
            }
        }

        private void AddProxyRoute(string proxyIp, string gatewayIp, int gatewayInterfaceIndex)
        {
            try
            {
                RunCommand(CMD_NETSH,
                    $"interface ipv4 add route {proxyIp}/32 nexthop={gatewayIp} interface=\"{gatewayInterfaceIndex}\" metric=0 store=active");
            }
            catch (Exception)
            {
                // If "add" fails, it's possible there's already a route to this proxy
                // server from a previous run of Outline which ResetRouting could
                // not remove; try "set" before failing.
                RunCommand(CMD_NETSH,
                     $"interface ipv4 set route {proxyIp}/32 nexthop={gatewayIp} interface=\"{gatewayInterfaceIndex}\" metric=0 store=active");
            }
        }

        private void DeleteProxyRoute(string proxyIp, int gatewayInterfaceIndex)
        {
            RunCommand(CMD_NETSH, $"interface ipv4 delete route {proxyIp}/32 interface=\"{gatewayInterfaceIndex}\"");
        }

        // Route IPv4 traffic through the router. Instead of deleting the default IPv4 gateway (0.0.0.0/0),
        // we resort to creating two more specific routes (see IPV4_SUBNETS) that take precedence over the
        // default gateway. This way, we need not worry about the default gateway being recreated with a lower
        // metric upon device sleep. This 'hack' was inspired by OpenVPN;
        // see https://github.com/OpenVPN/openvpn3/commit/d08cc059e7132a3d3aee3dcd946fce4c35b1ced3#diff-1d76f0fd7ec04c6d1398288214a879c5R358.
        private void AddIpv4Redirect()
        {
            foreach (string subnet in IPV4_SUBNETS)
            {
                try
                {
                    RunCommand(CMD_NETSH, $"interface ipv4 add route {subnet} nexthop={TAP_DEVICE_IP} interface={TAP_DEVICE_NAME} metric=0 store=active");
                }
                catch (Exception)
                {
                    RunCommand(CMD_NETSH, $"interface ipv4 set route {subnet} nexthop={TAP_DEVICE_IP} interface={TAP_DEVICE_NAME} metric=0 store=active");
                }
            }
        }

        private void RemoveIpv4Redirect()
        {
            foreach (string subnet in IPV4_SUBNETS)
            {
                RunCommand(CMD_NETSH, $"interface ipv4 delete route {subnet} interface={TAP_DEVICE_NAME}");
            }
        }

        private void StartRoutingIpv6()
        {
            foreach (string subnet in IPV6_SUBNETS)
            {
                RunCommand(CMD_NETSH, $"interface ipv6 delete route {subnet} interface={NetworkInterface.IPv6LoopbackInterfaceIndex}");
            }
        }

        // Outline does not currently support IPv6, so we resort to disabling it while the VPN is active to
        // prevent leakage. Removing the default IPv6 gateway is not enough since it gets re-created
        // through router advertisements and DHCP (disabling these or IPv6 routing altogether requires a
        // system reboot). Thus, we resort to creating three IPv6 routes (see IPV6_SUBNETS) to the loopback
        // interface that are more specific than the default route, causing IPv6 traffic to get dropped.
        private void StopRoutingIpv6()
        {
            foreach (string subnet in IPV6_SUBNETS)
            {
                try
                {
                    RunCommand(CMD_NETSH, $"interface ipv6 add route {subnet} interface={NetworkInterface.IPv6LoopbackInterfaceIndex} metric=0 store=active");
                }
                catch (Exception)
                {
                    RunCommand(CMD_NETSH, $"interface ipv6 set route {subnet} interface={NetworkInterface.IPv6LoopbackInterfaceIndex} metric=0 store=active");
                }
            }
        }

        // Routes reserved and private subnets through the default gateway so they bypass the VPN.
        private void AddReservedSubnetBypass(string gatewayIp, int gatewayInterfaceIndex)
        {
            foreach (string subnet in IPV4_RESERVED_SUBNETS)
            {
                try
                {
                    RunCommand(CMD_NETSH, $"interface ipv4 add route {subnet} nexthop={gatewayIp} interface=\"{gatewayInterfaceIndex}\" metric=0 store=active");
                }
                catch (Exception)
                {
                    RunCommand(CMD_NETSH, $"interface ipv4 set route {subnet} nexthop={gatewayIp} interface=\"{gatewayInterfaceIndex}\" metric=0 store=active");
                }
            }
        }

        // Removes reserved subnet routes created to bypass the VPN.
        private void RemoveReservedSubnetBypass(int gatewayInterfaceIndex)
        {
            foreach (string subnet in IPV4_RESERVED_SUBNETS)
            {
                RunCommand(CMD_NETSH, $"interface ipv4 delete route {subnet} interface=\"{gatewayInterfaceIndex}\"");
            }
        }

        // Runs a shell command synchronously.
        private void RunCommand(string cmd, string args)
        {
            Console.WriteLine($"running command: {cmd} {args}");

            var startInfo = new ProcessStartInfo(cmd);
            startInfo.Arguments = args;
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardError = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.CreateNoWindow = true;

            Process p = new Process();
            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            p.OutputDataReceived += (object sender, DataReceivedEventArgs e) =>
            {
                if (e == null || String.IsNullOrWhiteSpace(e.Data))
                {
                    return;
                }
                stdout.Append(e.Data);
            };
            p.ErrorDataReceived += (object sender, DataReceivedEventArgs e) =>
            {
                if (e == null || String.IsNullOrWhiteSpace(e.Data))
                {
                    return;
                }
                stderr.Append(e.Data);
            };
            p.StartInfo = startInfo;
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            p.WaitForExit();

            if (p.ExitCode != 0)
            {
                // NOTE: Do *not* add args to this error message because it's piped
                //       back to the client for inclusion in Sentry reports and
                //       effectively contain access keys.
                throw new Exception($"command exited with {p.ExitCode} " +
                    $"(stdout: {stdout.ToString()}, stderr: {stderr.ToString()})");
            }
        }

        // https://docs.microsoft.com/en-us/windows/desktop/api/ipmib/ns-ipmib-_mib_ipforwardrow
        [StructLayout(LayoutKind.Sequential)]
        internal class MIB_IPFORWARDROW
        {
            internal uint dwForwardDest;
            internal uint dwForwardMask;
            internal uint dwForwardPolicy;
            internal uint dwForwardNextHop;
            internal int dwForwardIfIndex;
            internal uint dwForwardType;
            internal uint dwForwardProto;
            internal uint dwForwardAge;
            internal uint dwForwardNextHopAS;
            internal uint dwForwardMetric1;
            internal uint dwForwardMetric2;
            internal uint dwForwardMetric3;
            internal uint dwForwardMetric4;
            internal uint dwForwardMetric5;
        }

        // https://docs.microsoft.com/en-us/windows/desktop/api/ipmib/ns-ipmib-_mib_ipforwardtable
        //
        // NOTE: Because of the variable-length array, Marshal.PtrToStructure will *not* populate
        //       the table field. See #GetSystemIpv4Gateway for how to traverse the rows.
        [StructLayout(LayoutKind.Sequential)]
        internal class MIB_IPFORWARDTABLE
        {
            internal uint dwNumEntries;
            internal MIB_IPFORWARDROW[] table;
        };

        // https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-getipforwardtable
        [DllImport("iphlpapi", CharSet = CharSet.Auto)]
        private extern static int GetIpForwardTable(IntPtr pIpForwardTable, ref int pdwSize, bool bOrder);

        // TODO: explain how this is essentially GetBestRoute which ignores the TAP device
        private void GetSystemIpv4Gateway(string proxyIp)
        {
            // TODO: handle failure
            var tapInterfaceIndex = NetworkInterface.GetAllNetworkInterfaces()
                .Where(i => i.Name == TAP_DEVICE_NAME)
                .FirstOrDefault().GetIPProperties().GetIPv4Properties().Index;

            var buffer = IntPtr.Zero;
            int bufferSize = 0;
            var result = GetIpForwardTable(buffer, ref bufferSize, true);
            buffer = Marshal.AllocHGlobal(bufferSize);
            result = GetIpForwardTable(buffer, ref bufferSize, true);
            MIB_IPFORWARDTABLE table = (MIB_IPFORWARDTABLE)Marshal.PtrToStructure(buffer, typeof(MIB_IPFORWARDTABLE));

            // TODO: consider non-0.0.0.0 gateways, like this implementation does:
            // https://github.com/reactos/reactos/blob/master/dll/win32/iphlpapi/iphlpapi_main.c
            IntPtr p = new IntPtr(buffer.ToInt64() + Marshal.SizeOf(table.dwNumEntries));
            MIB_IPFORWARDROW bestRow = null;
            for (int i = 0; i < table.dwNumEntries; i++)
            {
                MIB_IPFORWARDROW row = (MIB_IPFORWARDROW)Marshal.PtrToStructure(p, typeof(MIB_IPFORWARDROW));

                // must be a gateway.
                if (row.dwForwardDest != 0)
                {
                    continue;
                }

                // must not be on the TAP device.
                if (row.dwForwardIfIndex == tapInterfaceIndex)
                {
                    continue;
                }

                if (bestRow == null || row.dwForwardMetric1 < bestRow.dwForwardMetric1)
                {
                    bestRow = row;
                }

                p = new IntPtr(p.ToInt64() + Marshal.SizeOf(typeof(MIB_IPFORWARDROW)));
            }

            Marshal.FreeHGlobal(buffer);

            if (bestRow == null)
            {
                // TODO: yuck
                gatewayIp = null;
                throw new Exception("no gateway found");
            }

            gatewayIp = new IPAddress(BitConverter.GetBytes(bestRow.dwForwardNextHop)).ToString();
            gatewayInterfaceIndex = bestRow.dwForwardIfIndex;
        }

        // Updates the routing table, if necessary, in the event of a network change.
        //
        // Notes:
        //  - Does nothing if we think are not connected.
        //  - This function must *not* throw. If it does, the handler is unset.
        private void NetworkAddressChanged(object sender, EventArgs evt)
        {
            if (proxyIp == null)
            {
                eventLog.WriteEntry("network changed but Outline is not connected - doing nothing");
                return;
            }

            try
            {
                var previousGatewayIp = gatewayIp;
                var previousGatewayInterfaceIndex = gatewayInterfaceIndex;
                GetSystemIpv4Gateway(proxyIp);
                if (previousGatewayIp == gatewayIp && previousGatewayInterfaceIndex == gatewayInterfaceIndex)
                {
                    eventLog.WriteEntry($"network changed but gateway is the same - doing nothing");
                    return;
                }
                eventLog.WriteEntry($"network changed - gateway is now {gatewayIp} on interface {gatewayInterfaceIndex}");
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"network changed but cannot find a gateway: {e.Message}");
                SendConnectionStatusChange(ConnectionStatus.Reconnecting);
                return;
            }

            SendConnectionStatusChange(ConnectionStatus.Reconnecting);

            try
            {
                AddProxyRoute(proxyIp, gatewayIp, gatewayInterfaceIndex);
                eventLog.WriteEntry($"updated route to proxy");
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"could not update route to proxy: {e.Message}");
                // TODO: anything more to do? the client will remain disconnected
                return;
            }

            try
            {
                AddReservedSubnetBypass(gatewayIp, gatewayInterfaceIndex);
                eventLog.WriteEntry($"updated LAN bypass routes");
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"could not update LAN bypass routes: {e.Message}");
                // TODO: anything more to do? the client will remain disconnected
                return;
            }

            SendConnectionStatusChange(ConnectionStatus.Connected);
        }

        // Writes the connection status to the pipe, if it is connected. 
        private void SendConnectionStatusChange(ConnectionStatus status)
        {
            if (pipe == null || !pipe.IsConnected)
            {
                eventLog.WriteEntry("Cannot send connection status change, pipe not connected.", EventLogEntryType.Error);
                return;
            }
            ServiceResponse response = new ServiceResponse();
            response.action = ACTION_STATUS_CHANGED;
            response.statusCode = (int)ErrorCode.Success;
            response.connectionStatus = (int)status;
            try
            {
                WriteResponse(response);
            }
            catch (Exception e)
            {
                eventLog.WriteEntry($"Failed to send connection status change: {e.Message}");
            }
        }

        public string GetNetworkInfo()
        {
            return String.Join(", ", NetworkInterface.GetAllNetworkInterfaces()
                .Select(a => this.GetAdapterInfo(a)));
        }

        private string GetAdapterInfo(NetworkInterface adapter)
        {
            var numIpv4Gateways = adapter.GetIPProperties().GatewayAddresses
                  .Select(g => g.Address)
                  .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                  .Count();
            var numIpv6Gateways = adapter.GetIPProperties().GatewayAddresses
                  .Select(g => g.Address)
                  .Where(a => a.AddressFamily == AddressFamily.InterNetworkV6)
                  .Count();

            return $"{adapter.Name} ({adapter.OperationalStatus}): " + (
                adapter.Supports(NetworkInterfaceComponent.IPv4) ?
                    $"{numIpv4Gateways} x ipv4 gateways" :
                    "ipv4 disabled") + ", " + (
                adapter.Supports(NetworkInterfaceComponent.IPv6) ?
                    $"{numIpv6Gateways} x ipv6 gateways" :
                    "ipv6 disabled");
        }
    }

    [DataContract]
    internal class ServiceRequest
    {
        [DataMember]
        internal string action;
        [DataMember]
        internal Dictionary<string, string> parameters;
    }

    [DataContract]
    internal class ServiceResponse
    {
        [DataMember]
        internal string action;
        [DataMember]
        internal int statusCode;
        [DataMember]
        internal string errorMessage;
        [DataMember]
        internal int connectionStatus;
    }

    public enum ErrorCode
    {
        Success = 0,
        GenericFailure = 1
    }

    public enum ConnectionStatus
    {
        Connected = 0,
        Disconnected = 1,
        Reconnecting = 2
    }
}
