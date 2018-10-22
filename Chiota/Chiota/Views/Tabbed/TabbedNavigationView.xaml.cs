using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Chiota.Views.Tabbed
{
	[XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class TabbedNavigationView : TabbedPage
	{
		public TabbedNavigationView ()
		{
			InitializeComponent ();
		}
	}
}