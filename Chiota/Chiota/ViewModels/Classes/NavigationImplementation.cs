using System;
using System.Collections.Generic;
using System.Text;
using Xamarin.Forms;

namespace Chiota.ViewModels.Classes
{
    public class NavigationImplementation
    {
        #region Properties

        public INavigation Navigation { get; set; }

        public Page CurrentPage { get; set; }
        public Page LastPage { get; set; }
        public Page RootPage { get; set; }

        public object InitObject { get; set; }
        public object ReverseObject { get; set; }

        #endregion
    }
}
