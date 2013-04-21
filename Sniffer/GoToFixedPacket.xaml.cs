using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Sniffer
{
    /// <summary>
    /// Interaction logic for GoToFixedPacket.xaml
    /// </summary>
    public partial class GoToFixedPacket : Window
    {
        public delegate void GoToFixedPacketHandler(object sender, int packetIndex);
        public event GoToFixedPacketHandler GoToFixedPacketEvent;

        public GoToFixedPacket()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            this.Close();
            if (GoToFixedPacketEvent != null)
            {
                GoToFixedPacketEvent(this, Convert.ToInt32(this.PacketNumber.Text.ToString()));
            }
        }
    }
}
