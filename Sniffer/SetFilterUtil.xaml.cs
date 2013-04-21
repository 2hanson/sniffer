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
    /// Interaction logic for SetFilterUtil.xaml
    /// </summary>
    public partial class SetFilterUtil : Window
    {
        private string filterRule;
        public delegate void ApplyFilterRuleHandler(object sender, string _filterRule);
        public event ApplyFilterRuleHandler ApplyFilterRuleEvent;
        private Dictionary<string, string> captureRules = new Dictionary<string, string>();
        public SetFilterUtil()
        {
            InitializeComponent();
            filterRule = "";
            Init();
        }

        void Init()
        {
            captureRules.Add("No ARP", "not arp");
            captureRules.Add("No IP", " not ip");
            captureRules.Add("No TCP", "not tcp");
            captureRules.Add("No UDP", "not udp");
            captureRules.Add("IP only", "ip");
            captureRules.Add("TCP only", "tcp");
            captureRules.Add("UDP only", "udp");
            captureRules.Add("ARP only", "arp");
            captureRules.Add("TCP/IP only", "ip and tcp");
        }

        public SetFilterUtil(string _filterRule)
        {
            this.filterRule = _filterRule;
            InitializeComponent();
            Init();
        }

        private void Apply_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
            this.filterRule = this.FilterStringLabel.Text;
            if (ApplyFilterRuleEvent != null)
            {
                ApplyFilterRuleEvent(this, this.filterRule);
            }
        }

        private void Cancle_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void DeleteFilter(object sender, RoutedEventArgs e)
        {
            ListBoxItem selectedItem = this.Filters.SelectedItem as ListBoxItem;
            if (selectedItem == null)
                return;
            if (captureRules.ContainsKey(selectedItem.Content.ToString()) == true)
            {
                captureRules.Remove(selectedItem.Content.ToString());
            }
            this.Filters.Items.Remove(this.Filters.SelectedItem);
        }

        private void AddFilter(object sender, RoutedEventArgs e)
        {
            if (this.FilterStringLabel.Text.Length != 0 && this.FilterNameLabel.Text.Length != 0)
            {
                if (captureRules.ContainsKey(this.FilterNameLabel.Text.ToString()) != true)
                {
                    captureRules.Add(this.FilterNameLabel.Text.ToString(), this.FilterStringLabel.Text.ToString());
                }
                else
                {
                    return;
                }
                ListBoxItem newListBoxItem = new ListBoxItem();
                newListBoxItem.Content = this.FilterNameLabel.Text.ToString();
                this.Filters.Items.Add(newListBoxItem);
            }
        }

        private void Filters_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ListBoxItem selectedItem = this.Filters.SelectedItem as ListBoxItem;
            if (selectedItem == null)
            {
                this.FilterStringLabel.Text = "";
                this.FilterNameLabel.Text = "";
                return;
            }
            if (captureRules.ContainsKey( selectedItem.Content.ToString()) == true)
            {
                this.FilterStringLabel.Text = captureRules[selectedItem.Content.ToString()];
                this.FilterNameLabel.Text = selectedItem.Content.ToString();
            }
        }
    }
}
