using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections.ObjectModel;
using System.ComponentModel;

namespace Sniffer.ViewModel
{
    public class InfoTreeViewModel
    {
        #region Data
        readonly ReadOnlyCollection<InfoViewModel> firstGeneration;
        readonly InfoViewModel rootInfo;
        #endregion data

        #region Contructor
        public InfoTreeViewModel(Info _rootInfo)
        {
            this.rootInfo = new InfoViewModel(_rootInfo);

            this.firstGeneration = new ReadOnlyCollection<InfoViewModel>(
                    new InfoViewModel[] { 
                        this.rootInfo
                    });
        }
        #endregion

        #region Properties
        #region FirstGeneration

        /// <summary>
        /// Returns a read-only collection containing the first Info 
        /// in the tree, to which the TreeView can bind.
        /// </summary>
        public ReadOnlyCollection<InfoViewModel> FirstGeneration
        {
            get { return this.firstGeneration; }
        }

        #endregion
        #endregion //Properties
    }
}
