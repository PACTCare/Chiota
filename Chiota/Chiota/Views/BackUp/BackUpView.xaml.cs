using Chiota.ViewModels.Classes;

namespace Chiota.Views.BackUp
{
    using Xamarin.Forms;
    using Xamarin.Forms.Xaml;

    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class BackUpView : ContentPage
    {
        public BackUpView()
        {
            InitializeComponent();

            if (BindingContext is BaseViewModel viewModel)
                viewModel.Setup(this);
        }
    }
}