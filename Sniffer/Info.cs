using System.Collections.Generic;

namespace Sniffer
{
    public class Info
    {
        readonly List<Info> children = new List<Info>();

        public IList<Info> Children
        {
            get { return this.children; }
        }

        public string Detail { get; set; }
    }
}
