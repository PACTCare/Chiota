using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Chiota.Views.Chat
{
	[XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class ChatView : ContentPage
	{
		public ChatView ()
		{
			InitializeComponent ();
		}
	}
}