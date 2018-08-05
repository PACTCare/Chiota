using System;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;
using Chiota.ViewModels;
using Chiota.Extensions;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupPageModels;
using Chiota.Popups.PopupPages;
using Chiota.ViewModels.Classes;

namespace Chiota.Views
{
    /// <summary>
    /// The login page.
    /// </summary>
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class LoginPage : ContentPage
    {
        public LoginPage()
        {
            this.InitializeComponent();

            //Setup the viewmodel
            if (BindingContext is BaseViewModel viewmodel)
            {
                viewmodel.Setup(this);

                if(viewmodel is LoginViewModel loginviewmodel)
                this.RandomSeed.Completed += (object sender, EventArgs e) =>
                {
                    loginviewmodel.SubmitCommand.Execute(null);
                };
            }
        }
    }
}