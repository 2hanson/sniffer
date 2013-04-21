using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;
using System.Collections.ObjectModel;

namespace Sniffer.ViewModel
{
    public class InfoViewModel : INotifyPropertyChanged
    {
        #region Data
        readonly ReadOnlyCollection<InfoViewModel> children;
        readonly InfoViewModel parent;
        readonly Info info;

        bool isExpanded;
        bool isSelected;
        #endregion //Data

        #region Constructors
        public InfoViewModel(Info _info)
            : this(_info, null)
        { 
        }

        private InfoViewModel(Info _info, InfoViewModel _parent)
        {
            this.info = _info;
            this.parent = _parent;

            this.children = new ReadOnlyCollection<InfoViewModel>(
                (from __child in this.info.Children
                 select new InfoViewModel(__child, this))
                 .ToList<InfoViewModel>());
        }
        #endregion //Constructors

        #region Info Properties
        public ReadOnlyCollection<InfoViewModel> Children
        {
            get { return this.children; }
        }

        public string Detail
        {
            get { return this.info.Detail; }
        }
        #endregion //info properties

        #region Presentation Members
        
        #region IsExpand

        /// <summary>
        /// Gets/sets whether the TreeViewItem 
        /// associated with this object is expanded.
        /// </summary>
        public bool IsExpanded
        {
            get { return this.isExpanded; }
            set
            {
                if (value != this.isExpanded)
                {
                    this.isExpanded = value;
                    this.OnPropertyChanged("IsExpanded");
                }

                // Expand all the way up to the root.
                if (this.isExpanded && this.parent != null)
                    this.parent.IsExpanded = true;
            }
        }

        #endregion

        #region IsSelected

        /// <summary>
        /// Gets/sets whether the TreeViewItem 
        /// associated with this object is selected.
        /// </summary>
        public bool IsSelected
        {
            get { return this.isSelected; }
            set
            {
                if (value != this.isSelected)
                {
                    this.isSelected = value;
                    this.OnPropertyChanged("IsSelected");
                }
            }
        }

        #endregion // IsSelected

        #region Parent

        public InfoViewModel Parent
        {
            get { return this.parent; }
        }

        #endregion // Parent

        #endregion

        #region INotifyPropertyChanged Members

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            if (this.PropertyChanged != null)
                this.PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion // INotifyPropertyChanged Members
    }
}