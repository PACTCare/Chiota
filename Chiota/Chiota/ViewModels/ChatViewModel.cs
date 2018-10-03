using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
  using System.Collections.Generic;
  using System.Collections.ObjectModel;
  using System.Linq;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Messenger;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.GetMessages;
  using Chiota.Messenger.Usecase.SendMessage;
  using Chiota.Presenters;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  using Xamarin.Forms;

  public class ChatViewModel : BaseViewModel
  {
    private readonly ListView messagesListView;

    private readonly Contact contact;

    private Address currentChatAddress;

    private IAsymmetricKeyPair ntruChatKeyPair;

    private string outgoingText;

    private ObservableCollection<MessageViewModel> messagesList;

    private bool loadNewMessages;

    public ChatViewModel(ListView messagesListView, Contact contact)
    {
      this.contact = contact;
      this.currentChatAddress = new Address(contact.ChatAddress);
      this.messagesListView = messagesListView;
      this.Messages = new ObservableCollection<MessageViewModel>();
      this.OutGoingText = null;
    }

    public string OutGoingText
    {
      get => this.outgoingText;
      set
      {
        this.outgoingText = value;
        this.OnPropertyChanged();
      }
    }

    public ICommand SendCommand => new Command(async () => { await this.SendMessage(); });

    public ObservableCollection<MessageViewModel> Messages
    {
      get => this.messagesList;
      set
      {
        this.messagesList = value;
        this.OnPropertyChanged();
      }
    }

    private bool PageIsShown { get; set; }

    public async void OnAppearing()
    {
      this.PageIsShown = true;
      this.loadNewMessages = true;
      this.GetMessagesAsync(this.Messages);
    }

    public void OnDisappearing()
    {
      this.PageIsShown = false;
    }

    public async void MessageRestriction(Entry entry)
    {
      if (string.IsNullOrEmpty(entry.Text) || entry.Text.Length <= Constants.MessageCharacterLimit)
      {
        return;
      }

      entry.Text.Remove(entry.Text.Length - 1);
      await this.DisplayAlertAsync("Error", $"Message is too long. Limit is {Constants.MessageCharacterLimit} characters.");
    }

    private async Task SendMessage()
    {
      if (this.OutGoingText?.Length > 0)
      {
        await this.DisplayLoadingSpinnerAsync("Sending Message");

        this.loadNewMessages = false;

        var interactor = DependencyResolver.Resolve<IUsecaseInteractor<SendMessageRequest, SendMessageResponse>>();
        var response = await interactor.ExecuteAsync(
          new SendMessageRequest
            {
              ChatAddress = this.currentChatAddress,
              KeyPair = this.ntruChatKeyPair,
              Message = this.OutGoingText,
              UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

        this.loadNewMessages = true;
        await this.AddNewMessagesAsync(this.Messages);
        this.OutGoingText = null;

        await this.PopPopupAsync();

        await SendMessagePresenter.Present(this, response);
      }
    }

    private async void GetMessagesAsync(ICollection<MessageViewModel> messages)
    {
      while (this.PageIsShown)
      {
        await this.AddNewMessagesAsync(messages);
        await Task.Delay(9000);
      }
    }

    private async Task AddNewMessagesAsync(ICollection<MessageViewModel> messages)
    {
      if (this.loadNewMessages)
      {
        this.loadNewMessages = false;
        var response = await DependencyResolver.Resolve<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>().ExecuteAsync(
                                 new GetMessagesRequest
                                   {
                                     ChatAddress = this.currentChatAddress,
                                     ChatKeyPair = this.ntruChatKeyPair,
                                     ChatKeyAddress = new Address(this.contact.ChatKeyAddress),
                                     UserKeyPair = UserService.CurrentUser.NtruKeyPair
                                   });

        this.currentChatAddress = response.CurrentChatAddress;
        this.ntruChatKeyPair = response.ChatKeyPair;

        var newMessages = GetMessagesPresenter.Present(response, this.contact);

        if (newMessages.Count > 0)
        {
          foreach (var m in newMessages)
          {
            if (messages.Any(message => message.MessagDateTime.Ticks == m.MessagDateTime.Ticks))
            {
              continue;
            }

            messages.Add(m);
          }

          this.ScrollToNewMessage();
        }

        this.loadNewMessages = true;
      }
    }

    private void ScrollToNewMessage()
    {
      var lastMessage = this.messagesListView?.ItemsSource?.Cast<object>().LastOrDefault();

      if (lastMessage != null)
      {
        this.messagesListView.ScrollTo(lastMessage, ScrollToPosition.MakeVisible, false);
      }
    }
  }
}