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
using System.Windows.Navigation;
using System.Windows.Shapes;
using Sniffer.ViewModel;

namespace Sniffer
{
    /// <summary>
    /// Interaction logic for InfoTreeViewControl.xaml
    /// </summary>
    public partial class InfoTreeViewControl : UserControl
    {
        readonly InfoTreeViewModel infoTree;

        public InfoTreeViewControl()
        {
            InitializeComponent();

            //Get raw info tree data
            Info rootInfo = GetFamilyTree();

            //Create UI-friendly wrappers around the 
            //raw data objects(the view model)
            this.infoTree = new InfoTreeViewModel(rootInfo);

            //let the UI bind to the view-model
            base.DataContext = this.infoTree;
        }

        public InfoTreeViewControl(Info rootInfo)
        {
            InitializeComponent();

            //Create UI-friendly wrappers around the 
            //raw data objects(the view model)
            this.infoTree = new InfoTreeViewModel(rootInfo);

            //let the UI bind to the view-model
            base.DataContext = this.infoTree;
        }

        public Info GetFamilyTree()
        {
            // In a real app this method would access a database.
            return new Info
            {
                Detail = "David Weatherbeam",
                Children =
                {
                    new Info
                    {
                        Detail="Alberto Weatherbeam",
                        Children=
                        {
                            new Info
                            {
                                Detail="Zena Hairmonger",
                                Children=
                                {
                                    new Info
                                    {
                                        Detail="Sarah Applik",
                                    }
                                }
                            },
                            new Info
                            {
                                Detail="Jenny van Machoqueen",
                                Children=
                                {
                                    new Info
                                    {
                                        Detail="Nick van Machoqueen",
                                    },
                                    new Info
                                    {
                                        Detail="Matilda Porcupinicus",
                                    },
                                    new Info
                                    {
                                        Detail="Bronco van Machoqueen",
                                    }
                                }
                            }
                        }
                    },
                    new Info
                    {
                        Detail="Komrade Winkleford",
                        Children=
                        {
                            new Info
                            {
                                Detail="Maurice Winkleford",
                                Children=
                                {
                                    new Info
                                    {
                                        Detail="Divinity W. Llamafoot",
                                    }
                                }
                            },
                            new Info
                            {
                                Detail="Komrade Winkleford, Jr.",
                                Children=
                                {
                                    new Info
                                    {
                                        Detail="Saratoga Z. Crankentoe",
                                    },
                                    new Info
                                    {
                                        Detail="Excaliber Winkleford",
                                    }
                                }
                            }
                        }
                    }
                }
            };
        }

        private void TreeView_MouseWheel(object sender, MouseWheelEventArgs e)
        {
            //e.Handled = false;
        }
    }
}
