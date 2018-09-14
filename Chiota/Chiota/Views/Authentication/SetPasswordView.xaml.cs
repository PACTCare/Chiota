namespace Chiota.Views.Authentication
{
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class SetPasswordView : ContentPage
    {
        public SetPasswordView()
        {
            this.InitializeComponent();

            //Setup the pagemodel
            if (this.BindingContext is BaseViewModel viewmodel)
                viewmodel.Setup(this);
        }
    }
}