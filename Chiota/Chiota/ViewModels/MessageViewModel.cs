namespace Chiota.ViewModels
{
  using System;

  public class MessageViewModel : BaseViewModel
  {
    private string text;

    private string attachementUrl;

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
        this.RaisePropertyChanged();
      }
    }

    public string ImageSource
    {
      get => this.imageSource;
      set
      {
        this.imageSource = value;
        this.RaisePropertyChanged();
      }
    }

    public string ProfileImage
    {
      get => this.profileImage;
      set
      {
        this.profileImage = value;
        this.RaisePropertyChanged();
      }
    }

    public DateTime MessagDateTime
    {
      get => this.messageDateTime;
      set
      {
        this.messageDateTime = value;
        this.RaisePropertyChanged();
      }
    } 

    public bool IsIncoming
    {
      get => this.isIncoming;
      set
      {
        this.isIncoming = value;
        this.RaisePropertyChanged();
      }
    }

    public bool HasAttachement => !string.IsNullOrEmpty(this.attachementUrl);

    public string AttachementUrl
    {
      get => this.attachementUrl;
      set
      {
        this.attachementUrl = value;
        this.RaisePropertyChanged();
      }
    }
  }
}
