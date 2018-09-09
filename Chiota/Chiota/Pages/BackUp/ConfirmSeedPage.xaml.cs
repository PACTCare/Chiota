using Chiota.ViewModels.Classes;

using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Chiota.Pages.BackUp
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class ConfirmSeedPage : ContentPage
    {
        public ConfirmSeedPage()
        {
            this.InitializeComponent();

            //Setup the pagemodel
            if (BindingContext is BaseViewModel viewmodel)
                viewmodel.Setup(this);
        }
    }
}