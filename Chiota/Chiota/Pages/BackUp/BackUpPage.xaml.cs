using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.ViewModels.Classes;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Chiota.Pages.BackUp
{
	[XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class BackUpPage : ContentPage
	{
		public BackUpPage ()
		{
			InitializeComponent ();

		    //Setup the pagemodel
		    if (BindingContext is BaseViewModel viewmodel)
		        viewmodel.Setup(this);
        }
	}
}