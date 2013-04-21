using System.Windows;
using System.Windows.Controls;
using SharpPcap;

namespace Sniffer
{
    /// <summary>
    /// Interaction logic for InterfacesListView.xaml
    /// </summary>
    public partial class InterfacesListView : Window
    {
        public delegate void ChooseInterfaceHandler(object sender, int interfaceIndex, int captureMode);
        public event ChooseInterfaceHandler ChooseInterfaceEvent;

        public InterfacesListView()
        {
            InitializeComponent();
            ListInterfaces();
        }

        void ListInterfaces()
        {
            /* Retrieve the device list */
            var devices = CaptureDeviceList.Instance;

            /*If no device exists, print error */
            if (devices.Count < 1)
            {
                //string errorInfo = "No device found on this machine";
                TextBlock errorInfo = new TextBlock();
                errorInfo.Text = "No device found on this machine";
                this.StartButton.IsEnabled = false;
                this.Layout.Children.Add(errorInfo);
                return;
            }
            this.StartButton.IsEnabled = false;
            /* Scan the list printing every entry */
            foreach (var dev in devices)
            {
                /* Description */
                string interfaceInfo = dev.Description;
                RadioButton rb = new RadioButton();
                rb.Content = interfaceInfo;
                rb.Checked += new RoutedEventHandler(rb_Checked);
                this.InterfacesPanel.Children.Add(rb);
                //Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
            }
        }

        void rb_Checked(object sender, RoutedEventArgs e)
        {
            this.StartButton.IsEnabled = true;
            this.NormalMode.IsEnabled = true;
            this.PromiscuousMode.IsEnabled = true;
            this.PromiscuousMode.IsChecked = true;
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {

            this.Close();
            int captureMode = 1;//default is p
            int index = 0;
            foreach (var child in this.InterfacesPanel.Children)
            {
                if (child is RadioButton) {
                    RadioButton rb = child as RadioButton;
                    if (rb == this.NormalMode || rb == this.PromiscuousMode)
                    {
                        if (this.NormalMode.IsChecked == true)
                        {
                            captureMode = 0;
                        }
                        else if (this.PromiscuousMode.IsChecked == true)
                        {
                            captureMode = 1;
                        }

                        continue;
                    }
                    if (rb.IsChecked == true) {
                        break;
                    }
                    ++index;
                }
            }
            if (ChooseInterfaceEvent != null)
            {
                ChooseInterfaceEvent(this, index, captureMode);
            }

        }

        private void button1_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
