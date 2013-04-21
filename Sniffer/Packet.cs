namespace Sniffer
{
    public class CustomerPacket
    {
        public string packetNo { get; set; }
        public string packetcurTime { get; set; }
        public string packetSource { get; set; }
        public string packetDestination { get; set; }
        public string packetprotocol { get; set; }
        public string packetlength { get; set; }
        public string packetInfo { get; set; }

        public CustomerPacket()
        { }

        public CustomerPacket(string _pn, string _pt, string _ps, string _pd, string _pp, string _pl, string _pi)
        { 
            packetNo = _pn;
            packetcurTime = _pt;
            packetSource = _ps;
            packetDestination = _pd;
            packetprotocol = _pp;
            packetlength = _pl;
            packetInfo = _pi;
        }
    }
}
