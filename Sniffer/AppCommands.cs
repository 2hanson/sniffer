namespace Sniffer
{
    using System.Windows.Input;
    using System.Windows;
    using Microsoft.Windows.Controls.Ribbon;
    /// <summary>
    /// This class holds the global commands used by the application
    /// </summary>
    public static class AppCommands
    {
        #region RibbonCommands
        public static RibbonCommand Help
        {
            get { return (RibbonCommand)Application.Current.Resources["HelpCommand"]; }
        }
        public static RibbonCommand ClearBoard
        {
            get { return (RibbonCommand)Application.Current.Resources["ClearBoardCommand"]; }
        }
        public static RibbonCommand Stop
        {
            get { return (RibbonCommand)Application.Current.Resources["StopCommand"]; }
        }
        public static RibbonCommand Start
        {
            get { return (RibbonCommand)Application.Current.Resources["StartCommand"]; }
        }
        public static RibbonCommand GoToFirstPacket
        {
            get { return (RibbonCommand)Application.Current.Resources["GoToFirstPacketCommand"]; }
        }
        public static RibbonCommand GoToPacket
        {
            get { return (RibbonCommand)Application.Current.Resources["GoToPacketCommand"]; }
        }
        public static RibbonCommand GoToLastPacket
        {
            get { return (RibbonCommand)Application.Current.Resources["GoToLastPacketCommand"]; }
        }
        public static RibbonCommand SetFilter
        {
            get { return (RibbonCommand)Application.Current.Resources["SetFilterCommand"]; }
        }
        public static RibbonCommand FindInterfaces
        {
            get { return (RibbonCommand)Application.Current.Resources["FindInterfacesCommand"]; }
        }
        public static RibbonCommand Open
        {
            get { return (RibbonCommand)Application.Current.Resources["OpenCommand"]; }
        }
        public static RibbonCommand Save
        {
            get { return (RibbonCommand)Application.Current.Resources["SaveCommand"]; }
        }
        #endregion
    }
}
