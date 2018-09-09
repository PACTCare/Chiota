using Chiota.ViewModels.Classes;

using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Chiota.Pages.Authentication
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class NewSeedPage : ContentPage
    {
        public NewSeedPage()
        {
            this.InitializeComponent();

            //Setup the pagemodel
            if (BindingContext is BaseViewModel viewmodel)
                viewmodel.Setup(this);
        }
    }
}