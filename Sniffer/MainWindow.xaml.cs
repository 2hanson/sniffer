using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Windows.Controls.Ribbon;
using SharpPcap;
using System.Windows.Documents;
using System.Net;
using System.IO;
using System;
using SharpPcap.LibPcap;

namespace Sniffer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : RibbonWindow
    {
        #region
        public delegate void GetNextPacketDelegate();//定义委托
        private ObservableCollection<CustomerPacket> packets;
        private Collection<RawCapture> rawCapturesList = new Collection<RawCapture>();
        private ICaptureDevice device;
        private bool continueGetPacket;
        private long packetCount;
        private string filterRule;
        private bool canStopListening;
        private RawCapture selectedRawCapture;
        private int captureMode;
        CaptureFileWriterDevice captureFileWriter;
        ICaptureDevice readerDevice;
        #endregion

        public MainWindow()
        {
            InitializeComponent();
        }

        public long PacketCount
        {
            get
            {
                return this.packetCount;
            }
            set
            {
                this.packetCount = value;
                this.TotalDisplayed.Content = this.packetCount;
                this.TotalPackets.Content = this.packetCount;
            }
        }

        private void Init()
        {
            this.PacketCount = 0;
            this.device = null;
            this.continueGetPacket = false;
            this.filterRule = "";
            this.canStopListening = false;
            this.selectedRawCapture = null;
            this.captureMode = 1;//default is p mode, 0 is normal mode. 1 is p mode
        }

        private void OnIgnore(object sender, ExecutedRoutedEventArgs e)
        {
            MessageBox.Show("Written by Hanson(hangzhong.yu@gmail.com).");
        }

        private void FindInterfaces(object sender, RoutedEventArgs e)
        {
            InterfacesListView interfacesView = new InterfacesListView();
            interfacesView.Visibility = System.Windows.Visibility.Visible;
            interfacesView.ChooseInterfaceEvent += new InterfacesListView.ChooseInterfaceHandler(interfacesView_ChooseInterfaceEvent);
        }

        void interfacesView_ChooseInterfaceEvent(object sender, int interfaceIndex, int _captureMode)
        {
            /* Retrieve the device list */
            var devices = CaptureDeviceList.Instance;
            device = devices[interfaceIndex];
            this.captureMode = _captureMode;
        }

        //tcpdump filter to capture only TCP/IP packets if filter = "ip and tcp"
        private void SetFilter(object sender, ExecutedRoutedEventArgs e)
        {
            SetFilterUtil setFilterUtil = new SetFilterUtil(filterRule);
            setFilterUtil.Visibility = System.Windows.Visibility.Visible;
            setFilterUtil.ApplyFilterRuleEvent += new SetFilterUtil.ApplyFilterRuleHandler(setFilterUtil_ApplyFilterRuleEvent);
            //device.Filter = filter;
        }

        void setFilterUtil_ApplyFilterRuleEvent(object sender, string _filterRule)
        {
            this.filterRule = _filterRule;
        }

        private int ConvertString2Int(string str)
        {
            int flagvalue = 0;
            for (int index = 0; index < str.Length; ++index)
            {
                flagvalue *= 10;
                flagvalue += (str[index] - '0');
            }

            return flagvalue;
        }

        private CustomerPacket AchieiveNewPacket(RawCapture packet)
        {
            string source = "";
            string destination = "";
            string protocol = "";
            string info = "";
            var currentPacket = PacketDotNet.Packet.ParsePacket(packet.LinkLayerType, packet.Data);
            var tempPacket = currentPacket;

            while (tempPacket.PayloadPacket != null)
            {
                tempPacket = tempPacket.PayloadPacket;
            }

            if (tempPacket is PacketDotNet.ApplicationPacket)
            {
                var applicationPacket = tempPacket as PacketDotNet.ApplicationPacket;
                string headerString = "";
                for (int index = 12; index <= 15; ++index)
                {
                    if (index == 12)
                    {
                        headerString += (char)(ConvertString2Int(applicationPacket.Header[index].ToString()));
                    }
                    headerString += (char)(ConvertString2Int(applicationPacket.Header[index].ToString()));
                }

                if (headerString.CompareTo("HTTP") == 0)
                {
                    protocol = "HTTP";
                }
                else if (applicationPacket.ParentPacket is PacketDotNet.UdpPacket)
                {
                    protocol = "UDP";
                }
                else
                {
                    protocol = "TCP";
                }

                var ipPacket = tempPacket.ParentPacket.ParentPacket as PacketDotNet.IpPacket;
                source = ipPacket.SourceAddress.ToString();
                destination = ipPacket.DestinationAddress.ToString();
            }
            else if (tempPacket is PacketDotNet.TcpPacket)
            {
                protocol = "TCP";
                var ipPacket = tempPacket.ParentPacket as PacketDotNet.IpPacket;
                source = ipPacket.SourceAddress.ToString();
                destination = ipPacket.DestinationAddress.ToString();
                var tcpPacket = tempPacket as PacketDotNet.TcpPacket;
                if ((tcpPacket.DestinationPort.ToString().CompareTo("80") == 0) || (tcpPacket.DestinationPort.ToString().CompareTo("8080") == 0))
                {
                    protocol = "HTTP";
                }
                else if (tcpPacket.DestinationPort.ToString().CompareTo("1900") == 0)
                {
                    protocol = "SSDP";
                }

            }
            else if (tempPacket is PacketDotNet.UdpPacket)
            {
                protocol = "UDP";
                var ipPacket = tempPacket.ParentPacket as PacketDotNet.IpPacket;
                source = ipPacket.SourceAddress.ToString();
                destination = ipPacket.DestinationAddress.ToString();
                var udpPacket = tempPacket as PacketDotNet.UdpPacket;
                if (udpPacket.DestinationPort.ToString().CompareTo("80") == 0 || udpPacket.DestinationPort.ToString().CompareTo("8080") == 0)
                {
                    protocol = "HTTP";
                }
                else if (udpPacket.DestinationPort.ToString().CompareTo("1900") == 0)
                {
                    protocol = "SSDP";
                }
            }
            else if (tempPacket is PacketDotNet.IpPacket)
            {
                if (tempPacket is PacketDotNet.IPv4Packet)
                {
                    protocol = "Ipv4";
                }
                else
                {
                    protocol = "Ipv6";
                }
                var ipPacket = tempPacket as PacketDotNet.IpPacket;
                source = ipPacket.SourceAddress.ToString();
                destination = ipPacket.DestinationAddress.ToString();
            }
            else if (tempPacket is PacketDotNet.ARPPacket)
            {
                var arpPacket = tempPacket as PacketDotNet.ARPPacket;
                source = arpPacket.SenderHardwareAddress.ToString();
                destination = arpPacket.TargetHardwareAddress.ToString();
                protocol = "ARP";
                //info = System.Text.Encoding.ASCII.GetString(arpPacket.Bytes);
            }
            else if (tempPacket is PacketDotNet.EthernetPacket)
            {
                var ethernetPacket = tempPacket as PacketDotNet.EthernetPacket;
                source = ethernetPacket.SourceHwAddress.ToString();
                destination = ethernetPacket.DestinationHwAddress.ToString();
                protocol = "Ethernet";
                //info = System.Text.Encoding.ASCII.GetString(arpPacket.Bytes);
            }

            else if (tempPacket.ParentPacket is PacketDotNet.IpPacket)
            {
                var ipPacket = tempPacket.ParentPacket as PacketDotNet.IpPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                source = srcIp.ToString();
                destination = dstIp.ToString();
                protocol = ipPacket.Protocol.ToString();
                //ipPacket.Bytes
            }
            else if (tempPacket.ParentPacket is PacketDotNet.TcpPacket)
            {
                var tcpPacket = tempPacket.ParentPacket as PacketDotNet.TcpPacket;
                source = ((PacketDotNet.IpPacket)tcpPacket.ParentPacket).SourceAddress.ToString();
                destination = ((PacketDotNet.IpPacket)tcpPacket.ParentPacket).DestinationAddress.ToString();
                protocol = ((PacketDotNet.IpPacket)tcpPacket.ParentPacket).Protocol.ToString();
            }
            else if (tempPacket.ParentPacket is PacketDotNet.UdpPacket)
            {
                var udpPacket = tempPacket.ParentPacket as PacketDotNet.UdpPacket;
                source = ((PacketDotNet.IpPacket)udpPacket.ParentPacket).SourceAddress.ToString();
                destination = ((PacketDotNet.IpPacket)udpPacket.ParentPacket).DestinationAddress.ToString();
                protocol = ((PacketDotNet.IpPacket)udpPacket.ParentPacket).Protocol.ToString();
            }
            else if (tempPacket.ParentPacket is PacketDotNet.EthernetPacket)
            {
                var ethernetPacket = tempPacket.ParentPacket as PacketDotNet.EthernetPacket;
                source = ethernetPacket.SourceHwAddress.ToString();
                destination = ethernetPacket.DestinationHwAddress.ToString();
                protocol = ethernetPacket.Type.ToString();
            }
           
            return new CustomerPacket((PacketCount++).ToString(), packet.Timeval.ToString(), source, destination, protocol, packet.Data.Length.ToString(), info);
        }

        public void GetNextPacket()
        {

            RawCapture packet;

            // Capture packets using GetNextPacket()
            if ((packet = device.GetNextPacket()) != null)
            {
                captureFileWriter.Write(packet);


                rawCapturesList.Add(packet);

                CustomerPacket curpacket = AchieiveNewPacket(packet);
                if (packets == null)
                {
                    packets = new ObservableCollection<CustomerPacket>();
                    packets.Add(curpacket);
                    this.ViewBody.ItemsSource = packets;
                }
                else
                {
                    try
                    {
                        //此处可能会有溢出
                        packets.Add(curpacket);
                    }
                    catch
                    {
                        this.continueGetPacket = false;
                    }
                    finally
                    {

                    }
                }
            }

            if (this.continueGetPacket)
            {
                this.ViewBody.Dispatcher.BeginInvoke(DispatcherPriority.SystemIdle, new GetNextPacketDelegate(GetNextPacket));
            }
        }

        private void StopListening(object sender, ExecutedRoutedEventArgs e)
        {
            this.continueGetPacket = false;
            this.canStopListening = false;
        }

        private void StartListening(object sender, ExecutedRoutedEventArgs e)
        {
            if (device == null)
            {
                FindInterfaces(this, e);
                if (device == null)
                {
                    return;
                }
            }

            CaptureBegin();
        }

        private void CaptureBegin()
        {
            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            if (captureMode == 1)
            {
                device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            }
            else
            {
                device.Open(DeviceMode.Normal, readTimeoutMilliseconds);
            }
            string pcapFile = System.AppDomain.CurrentDomain.BaseDirectory;
            pcapFile += "\\pcapFile.Sniffer";
            captureFileWriter = new CaptureFileWriterDevice((LibPcapLiveDevice)this.device, pcapFile);

            this.canStopListening = true;
            //filter = "ip and tcp"
            if (this.filterRule != "")
            {
                device.Filter = this.filterRule;
            }

            this.continueGetPacket = true;
            this.PacketCount = 0;

            if (packets != null)
            {
                packets.Clear();
            }

            if (rawCapturesList != null)
            {
                rawCapturesList.Clear();
            }

            GetNextPacket();
        }

        private void CanStopListening(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = this.canStopListening;
        }

        private void ViewBody_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            int selectedIndex = this.ViewBody.SelectedIndex;
            if (selectedIndex == -1)
            {
                return;
            }
            this.selectedRawCapture = this.rawCapturesList[selectedIndex];

            ShowTreeViewWithThirdBoard();
        }

        private void ShowTreeViewWithThirdBoard()
        {
            this.TreeViewStack.Children.Clear();

            var currentPacket = PacketDotNet.Packet.ParsePacket(this.selectedRawCapture.LinkLayerType, this.selectedRawCapture.Data);
            this.ThirdBoard.Text = currentPacket.PrintHex();

            var tempPacket = currentPacket;
            while (tempPacket != null)
            {
                AnalysisPacket(tempPacket);
                tempPacket = tempPacket.PayloadPacket;
            }
        }

        private void CanStartListening(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = !this.canStopListening;
        }

        private void AnalysisPacket(PacketDotNet.Packet tempPacket)
        {
            if (tempPacket is PacketDotNet.EthernetPacket)
            {
                var ethernetPacket = tempPacket as PacketDotNet.EthernetPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "Ethernet, Src: ";
                tempRoot.Detail += ethernetPacket.SourceHwAddress.ToString();
                tempRoot.Detail += ", Dst: ";
                tempRoot.Detail += ethernetPacket.DestinationHwAddress.ToString();

                tempRoot.Children.Add(new Info
                {
                    Detail = ethernetPacket.SourceHwAddress.ToString(),
                    Children = 
                    {
                        new Info
                        {
                            Detail = ethernetPacket.SourceHwAddress.ToString(),
                        },
                    }
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = ethernetPacket.DestinationHwAddress.ToString(),
                    Children = 
                    {
                        new Info
                        {
                            Detail = ethernetPacket.DestinationHwAddress.ToString(),
                        },
                    }
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = ethernetPacket.Type.ToString(),
                });

                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.IpPacket)
            {
                Info tempRoot = new Info();
                if (tempPacket is PacketDotNet.IPv4Packet)
                {
                    tempRoot.Detail = "Internet Protocol Version 4, Src: ";
                }
                else
                {
                    tempRoot.Detail = "Internet Protocol Version 6, Src: ";
                }
                var ipPacket = tempPacket as PacketDotNet.IpPacket;
                tempRoot.Detail += ipPacket.SourceAddress.ToString();
                tempRoot.Detail += ", Dst: ";
                tempRoot.Detail += ipPacket.DestinationAddress.ToString();

                tempRoot.Children.Add(new Info
               {
                   Detail = "Version: " + ipPacket.Version.ToString(),
               });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Header Length: " + ipPacket.HeaderLength.ToString(),
                });

                tempRoot.Children.Add(new Info
                {
                    Detail = "Total Length: " + ipPacket.TotalLength.ToString(),
                });

                if (ipPacket.Protocol.ToString().CompareTo("TCP") == 0)
                {
                    string flags = ipPacket.Header[6].ToString();
                    int flagvalue = 0;
                    for (int index = 0; index < flags.Length; ++index)
                    {
                        flagvalue *= 10;
                        flagvalue += (flags[index] - '0');
                    }
                    string flagString;
                    int reserverdbit = 1;
                    string rdetail = "";
                    int dofragmentbit;
                    string dofragmentDetail = "";
                    int morefragmentbit;
                    string morefragmentDetail = "";
                    if ((flagvalue & 128) != 0)
                    {
                        reserverdbit = 0;
                        rdetail = "Not set";
                    }
                    else
                    {
                        reserverdbit = 1;
                        rdetail = "Set";
                    }

                    if ((flagvalue & 64) == 0)
                    {
                        dofragmentbit = 0;
                        dofragmentDetail = "Not set";
                        flagString = "Don't frament";
                    }
                    else
                    {
                        dofragmentbit = 1;
                        dofragmentDetail = "Set";
                         flagString = "Frament";
                    }

                    if ((flagvalue & 32) == 0)
                    {
                        morefragmentbit = 0;
                        morefragmentDetail = "Not set";
                    }
                    else
                    {
                        morefragmentbit = 1;
                        morefragmentDetail = "Set";
                    }

                    
                    tempRoot.Children.Add(new Info
                    {
                        Detail = "Flags: 0x02 (" + flagString + ")",
                        Children = 
                        {
                            new Info
                            {
                                Detail =reserverdbit+ "... .... = Reserved bit: " + rdetail,

                            },
                            new Info
                            {
                                Detail ="." +dofragmentbit+ ".. .... = Don't fragment: "+dofragmentDetail,
                            },
                            new Info
                            {
                                Detail =".."+ morefragmentbit+ ". .... = More fragment: "+morefragmentDetail,
                            },
                        }
                    });

                }
                else if (ipPacket.Protocol.ToString().CompareTo("UDP") == 0)
                {
                    string flags = ipPacket.Header[6].ToString();
                    int flagvalue = 0;
                    for (int index = 0; index < flags.Length; ++index)
                    {
                        flagvalue *= 10;
                        flagvalue += (flags[index] - '0');
                    }

                    int reserverdbit = 1;
                    string rdetail = "";
                    int dofragmentbit;
                    string dofragmentDetail = "";
                    int morefragmentbit;
                    string morefragmentDetail = "";
                    if ((flagvalue & 128) != 0)
                    {
                        reserverdbit = 0;
                        rdetail = "Not set";
                    }
                    else
                    {
                        reserverdbit = 1;
                        rdetail = "Set";
                    }

                    if ((flagvalue & 64) == 0)
                    {
                        dofragmentbit = 0;
                        dofragmentDetail = "Not set";
                    }
                    else
                    {
                        dofragmentbit = 1;
                        dofragmentDetail = "Set";
                    }

                    if ((flagvalue & 32) == 0)
                    {
                        morefragmentbit = 0;
                        morefragmentDetail = "Not set";
                    }
                    else
                    {
                        morefragmentbit = 1;
                        morefragmentDetail = "Set";
                    }


                    tempRoot.Children.Add(new Info
                    {
                        Detail = "Flags: 0x00 ",
                        Children = 
                        {
                            new Info
                            {
                                Detail =reserverdbit+ "... .... = Reserved bit: " + rdetail,

                            },
                            new Info
                            {
                                Detail ="." +dofragmentbit+ ".. .... = Don't fragment: "+dofragmentDetail,
                            },
                            new Info
                            {
                                Detail =".."+ morefragmentbit+ ". .... = More fragment: "+morefragmentDetail,
                            },
                        }
                    });

                }

                tempRoot.Children.Add(new Info
               {
                   Detail = "Time To Live: " + ipPacket.TimeToLive.ToString(),
               });

                tempRoot.Children.Add(new Info
               {
                   Detail = "Protocol: " + ipPacket.Protocol.ToString(),
               });

                tempRoot.Children.Add(new Info
                {
                    Detail = "Source: " + ipPacket.SourceAddress.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Destination: " + ipPacket.DestinationAddress.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.ARPPacket)
            {
                var arpPacket = tempPacket as PacketDotNet.ARPPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "Address Resolution Protocol (" + arpPacket.Operation.ToString() + ")";
                tempRoot.Children.Add(new Info
                {
                    Detail = "Hardware type: " + arpPacket.HardwareAddressType.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Protocol type: " + arpPacket.ProtocolAddressType.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Hardware Size: " + arpPacket.HardwareAddressLength.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Protocol size: " + arpPacket.ProtocolAddressLength.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Opcode: " + arpPacket.Operation.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Sender Mac address: " + arpPacket.SenderHardwareAddress.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Sender Ip address: " + arpPacket.SenderProtocolAddress.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Target Mac address: " + arpPacket.TargetHardwareAddress.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Target Ip address: " + arpPacket.TargetProtocolAddress.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.UdpPacket)
            {
                var udpPacket = tempPacket as PacketDotNet.UdpPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "User Datagram Protocol, Src Port: " + udpPacket.SourcePort.ToString() + ", Dst Port: " + udpPacket.DestinationPort.ToString();

                tempRoot.Children.Add(new Info
                {
                    Detail = "Source Port: " + udpPacket.SourcePort.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Destination Port: " + udpPacket.DestinationPort.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Checksum: " + udpPacket.Checksum.ToString(),
                    Children = { new Info
                    {
                        Detail = udpPacket.Checksum.ToString(),
                    },
                    }
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
                if ((udpPacket.DestinationPort.ToString().CompareTo("80") == 0) || (udpPacket.DestinationPort.ToString().CompareTo("8080") == 0) || (udpPacket.DestinationPort.ToString().CompareTo("1900") == 0))
                {
                    Info temp = new Info();
                    temp.Detail = "Hypertext Transfer Protocol";
                    try
                    {
                        string str = System.Text.ASCIIEncoding.ASCII.GetString(tempPacket.Bytes);
                        temp.Children.Add(new Info
                        {
                            Detail = str,
                        });
                    }
                    catch
                    { }

                    InfoTreeViewControl ifvc1 = new InfoTreeViewControl(temp);
                    this.TreeViewStack.Children.Add(ifvc1);
                }
            }
            else if (tempPacket is PacketDotNet.TcpPacket)
            {
                var tcpPacket = tempPacket as PacketDotNet.TcpPacket;
                Info tempRoot = new Info();

                tempRoot.Detail = "Transmission Control Protocol, Src Port: " + tcpPacket.SourcePort.ToString() + ", Dst Port: " + tcpPacket.DestinationPort.ToString() + ", Seq: " + tcpPacket.SequenceNumber.ToString() + ", Ack: " + tcpPacket.Ack.ToString();
                tempRoot.Children.Add(new Info
                {
                    Detail = "Source Port: " + tcpPacket.SourcePort.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Destination Port: " + tcpPacket.DestinationPort.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Sequence number: " + tcpPacket.SequenceNumber.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Acknowledgement number: " + tcpPacket.AcknowledgmentNumber.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Header length: " + tcpPacket.Header.Length.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Flags: ",
                    Children = { new Info
                    {
                        Detail = tcpPacket.AllFlags.ToString(),
                    },
                    }
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Window zise value: " + tcpPacket.WindowSize.ToString(),
                });
                tempRoot.Children.Add(new Info
                {
                    Detail = "Checksum: " + tcpPacket.Checksum.ToString(),
                    Children = { new Info
                    {
                        Detail = tcpPacket.Checksum.ToString(),
                    },
                    }
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);

                if ((tcpPacket.DestinationPort.ToString().CompareTo("80") == 0) || (tcpPacket.DestinationPort.ToString().CompareTo("8080") == 0) || (tcpPacket.DestinationPort.ToString().CompareTo("1900") == 0))
                {
                    Info temp = new Info();
                    temp.Detail = "Hypertext Transfer Protocol";
                    try
                    {
                        string str = System.Text.ASCIIEncoding.ASCII.GetString(tempPacket.Bytes);
                        temp.Children.Add(new Info
                        {
                            Detail = str,
                        });
                    }
                    catch
                    { }

                    InfoTreeViewControl ifvc1 = new InfoTreeViewControl(temp);
                    this.TreeViewStack.Children.Add(ifvc1);
                }
            }
            else if (tempPacket is PacketDotNet.ApplicationPacket)
            {
                var applicationPacket = tempPacket as PacketDotNet.ApplicationPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "Data";
                tempRoot.Children.Add(new Info
                {
                    Detail = applicationPacket.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.ICMPv4Packet)
            {
                var iCMPv4Packet = tempPacket as PacketDotNet.ICMPv4Packet;
                Info tempRoot = new Info();
                tempRoot.Detail = "Internet Control Message Protocol v4";
                tempRoot.Children.Add(new Info
                {
                    Detail = "Checksum: " + iCMPv4Packet.Checksum.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.ICMPv6Packet)
            {
                var iCMPv6Packet = tempPacket as PacketDotNet.ICMPv6Packet;
                Info tempRoot = new Info();
                tempRoot.Detail = "Internet Control Message Protocol v6";
                tempRoot.Children.Add(new Info
                {
                    Detail = "Checksum: " + iCMPv6Packet.Checksum.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.Ieee80211RadioPacket)
            {
                var ieee80211RadioPacket = tempPacket as PacketDotNet.Ieee80211RadioPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "Ieee80211RadioPacket";
                tempRoot.Children.Add(new Info
                {
                    //Detail = ieee80211RadioPacket.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.DataLinkPacket)
            {
                var dataLinkPacket = tempPacket as PacketDotNet.DataLinkPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "DataLinkPacket";
                tempRoot.Children.Add(new Info
                {
                    // Detail = dataLinkPacket.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.Ieee80211MacFrame)
            {
                var ieee80211MacFrame = tempPacket as PacketDotNet.Ieee80211MacFrame;
                Info tempRoot = new Info();
                tempRoot.Detail = "Ieee80211MacFrame";
                tempRoot.Children.Add(new Info
                {
                    // Detail = ieee80211MacFrame.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.IGMPv2Packet)
            {
                var iGMPv2Packet = tempPacket as PacketDotNet.IGMPv2Packet;
                Info tempRoot = new Info();
                tempRoot.Detail = "IGMPv2Packet";
                tempRoot.Children.Add(new Info
                {
                    //Detail = iGMPv2Packet.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.InternetPacket)
            {
                var internetPacket = tempPacket as PacketDotNet.InternetPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "InternetPacket";
                tempRoot.Children.Add(new Info
                {
                    //Detail = internetPacket.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.LLDPPacket)
            {
                var lLDPPacket = tempPacket as PacketDotNet.LLDPPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "LLDPPacket";
                tempRoot.Children.Add(new Info
                {
                    //Detail = lLDPPacket.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.PPPPacket)
            {
                var pPPPacket = tempPacket as PacketDotNet.PPPPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "PPPPacket";
                tempRoot.Children.Add(new Info
                {
                    // Detail = pPPPacket.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.SessionPacket)
            {
                var sessionPacket = tempPacket as PacketDotNet.SessionPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "SessionPacket";
                tempRoot.Children.Add(new Info
                {
                    //Detail = sessionPacket.ToString(),
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.TransportPacket)
            {
                var transportPacket = tempPacket as PacketDotNet.TransportPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "TransportPacket";
                tempRoot.Children.Add(new Info
                {
                    Detail = "TransportPacket",
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else if (tempPacket is PacketDotNet.WakeOnLanPacket)
            {
                var wakeOnLanPacket = tempPacket as PacketDotNet.WakeOnLanPacket;
                Info tempRoot = new Info();
                tempRoot.Detail = "WakeOnLanPacket";
                tempRoot.Children.Add(new Info
                {
                    //Detail = "TransportPacket",
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
            else
            {
                Info tempRoot = new Info();
                tempRoot.Detail = "UnknowPacketType";
                tempRoot.Children.Add(new Info
                {
                    //Detail = "TransportPacket",
                });
                InfoTreeViewControl ifvc = new InfoTreeViewControl(tempRoot);
                this.TreeViewStack.Children.Add(ifvc);
            }
        }

        private void scrolls_MouseWheel(object sender, MouseWheelEventArgs e)
        {
            this.scrolls.ScrollToVerticalOffset(-e.Delta);
        }

        private void GoToFirstPacket(object sender, ExecutedRoutedEventArgs e)
        {
            this.ViewBody.ScrollIntoView(this.ViewBody.Items[0]);
            this.ViewBody.SelectedItem = this.ViewBody.Items[0];
        }

        private void GoToLastPacket(object sender, ExecutedRoutedEventArgs e)
        {
            int lastItemIndex = (int)this.PacketCount;
            this.ViewBody.ScrollIntoView(this.ViewBody.Items[lastItemIndex - 1]);
            this.ViewBody.SelectedItem = this.ViewBody.Items[lastItemIndex - 1];
        }

        private void CanGoToFirstPacketExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = this.ViewBody.HasItems;
        }

        private void CanGoToLastPacketExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = this.ViewBody.HasItems;
        }

        private void GoToPacket(object sender, ExecutedRoutedEventArgs e)
        {
            GoToFixedPacket gtfp = new GoToFixedPacket();
            gtfp.Visibility = System.Windows.Visibility.Visible;
            gtfp.GoToFixedPacketEvent += new GoToFixedPacket.GoToFixedPacketHandler(gtfp_GoToFixedPacketEvent);
        }

        void gtfp_GoToFixedPacketEvent(object sender, int packetIndex)
        {
            if (packetIndex < 0 && packetIndex >= this.PacketCount)
            {
                MessageBox.Show("Warning, the index is out of range!");
            }

            this.ViewBody.ScrollIntoView(this.ViewBody.Items[packetIndex]);
            this.ViewBody.SelectedItem = this.ViewBody.Items[packetIndex];
        }

        private void OnOpenFile(object sender, ExecutedRoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog ofd = new Microsoft.Win32.OpenFileDialog();
            ofd.InitialDirectory = System.AppDomain.CurrentDomain.BaseDirectory;
            ofd.Filter = "Text Files (*.sniffer)|*.sniffer";
            ofd.Multiselect = false;
            if (ofd.ShowDialog() == true)
            {
                if (packets != null)
                {
                    packets.Clear();
                }

                if (rawCapturesList != null)
                {
                    rawCapturesList.Clear();
                }
                try
                {
                    ClearBoard();

                    this.readerDevice = new CaptureFileReaderDevice(ofd.FileName);
                    this.readerDevice.OnPacketArrival += new PacketArrivalEventHandler(readerDevice_OnPacketArrival);
                    this.readerDevice.Open();
                    this.readerDevice.Capture();
                    this.readerDevice.OnPacketArrival -= new PacketArrivalEventHandler(readerDevice_OnPacketArrival);
                }
                catch { }
                // Open the device for capturing
            }
        }

        void readerDevice_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            rawCapturesList.Add(e.Packet);

            CustomerPacket curpacket = AchieiveNewPacket(e.Packet);
            if (packets == null)
            {
                packets = new ObservableCollection<CustomerPacket>();
                packets.Add(curpacket);
                this.ViewBody.ItemsSource = packets;
            }
            else
            {
                try
                {
                    //此处可能会有溢出
                    packets.Add(curpacket);
                }
                catch
                {
                    this.continueGetPacket = false;
                }
                finally
                {

                }
            }
        }

        private void OnSaveFile(object sender, ExecutedRoutedEventArgs e)
        {
            Microsoft.Win32.SaveFileDialog sfd = new Microsoft.Win32.SaveFileDialog();
            sfd.Filter = "Text Files (*.sniffer;)|*.sniffer";
            if (sfd.ShowDialog() == true)
            {
                string pcapFile = System.AppDomain.CurrentDomain.BaseDirectory;
                pcapFile += "\\pcapFile.Sniffer";
                File.Copy(pcapFile, sfd.FileName);
            }
        }

        private void CanSaveExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = (this.ViewBody.HasItems && !this.continueGetPacket);
        }

        private void CanOpenExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = !this.continueGetPacket;
        }

        private void ClearBoard_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            ClearBoard();
        }

        private void ClearBoard()
        {
            if (packets != null)
            {
                packets.Clear();
            }

            if (rawCapturesList != null)
            {
                rawCapturesList.Clear();
            }
            this.ThirdBoard.Text = "";
            this.TreeViewStack.Children.Clear();
            this.PacketCount = 0;
        }
    }
}
