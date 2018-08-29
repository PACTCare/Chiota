using Chiota.ViewModels.Classes;
using Xamarin.Forms;

namespace Chiota.ViewModels
{
  using System;

  public class MessageViewModel : BaseViewModel
  {
    private string text;

    private string imageSource;

    private string profileImage;

    private DateTime messageDateTime;

    private bool isIncoming;

    public string Text
    {
      get => this.text;
      set
      {
        this.text = value;
        this.OnPropertyChanged();
      }
    }

    public string ImageSource
    {
      get => this.imageSource;
      set
      {
        this.imageSource = value;
        this.OnPropertyChanged();
      }
    }

    public string ProfileImage
    {
      get => this.profileImage;
      set
      {
        this.profileImage = value;
        this.OnPropertyChanged();
      }
    }

    public DateTime MessagDateTime
    {
      get => this.messageDateTime;
      set
      {
        this.messageDateTime = value;
        this.OnPropertyChanged();
      }
    } 

    public bool IsIncoming
    {
      get => this.isIncoming;
      set
      {
        this.isIncoming = value;
        this.OnPropertyChanged();
      }
    }
  }
}
