using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Rg.Plugins.Popup.Pages;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Chiota.Popups.PopupPages
{
	[XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class DialogPopupPage : PopupPage
	{
		public DialogPopupPage ()
		{
			InitializeComponent ();
		}
	}
}