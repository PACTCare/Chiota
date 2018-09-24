using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.ViewModels.Classes;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Chiota.Views.Contact
{
	[XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class AddContactView : ContentPage
	{
		public AddContactView ()
		{
			InitializeComponent ();

		    if (BindingContext is BaseViewModel viewModel)
		        viewModel.Setup(this);
        }
	}
}