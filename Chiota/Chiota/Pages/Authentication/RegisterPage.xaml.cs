using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.PageModels.Classes;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Chiota.Pages.Authentication
{
	[XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class RegisterPage : ContentPage
	{
		public RegisterPage ()
		{
			InitializeComponent ();

		    //Setup the pagemodel
		    if (BindingContext is BasePageModel viewmodel)
		        viewmodel.Setup(this);
        }
	}
}