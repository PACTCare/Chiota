namespace Chiota.ViewModels
{
  using System;
  using System.Collections.Generic;
  using System.Collections.ObjectModel;
  using System.Globalization;
  using System.Linq;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  using Xamarin.Forms;

  public class ChatViewModel : BaseViewModel
  {
    public Action DisplayMessageTooLong;

    private readonly string profileImageUrl;

    private readonly User user;

    private readonly Contact contact;

    private readonly NtruKex ntruKex;

    private readonly ListView messagesListView;

    private DateTime lastPostDate;

    private string outgoingText;

    private ObservableCollection<MessageViewModel> messagesList;

    public ChatViewModel(ListView messagesListView, Contact contact, User user)
    {
      this.ntruKex = new NtruKex();
      this.profileImageUrl = contact.ImageUrl;
      this.user = user;
      this.MessageLoop = true;

      // reset hash short storage, because it's different for every chat
      this.user.TangleMessenger.ShorStorageHashes = new List<Hash>();

      this.contact = contact;
      contact.PublicNtruKey = this.GetContactPublicKey(); 

      this.Messages = new ObservableCollection<MessageViewModel>();
      this.messagesListView = messagesListView;
      this.GetMessagesAsync(this.Messages);

      this.OutGoingText = null;
      this.SendCommand = new Command(async () => { await this.SendMessage(); });
    }

    public bool MessageLoop { get; set; }

    public string OutGoingText
    {
      get => this.outgoingText;
      set
      {
        this.outgoingText = value;
        this.RaisePropertyChanged();
      }
    }

    public ICommand SendCommand { get; set; }

    public ObservableCollection<MessageViewModel> Messages
    {
      get => this.messagesList;
      set
      {
        this.messagesList = value;
        this.RaisePropertyChanged();
      }
    }

    private IAsymmetricKey GetContactPublicKey()
    {
      var trytes = this.user.TangleMessenger.GetMessages(this.contact.PublicKeyAdress);
      var contactInfos = IotaHelper.FilterRequestInfos(trytes);
      return contactInfos.PublicNtruKey;
    }

    private async Task SendMessage()
    {
      this.IsBusy = true;

      // No json object, because of the 106 character limit
      if (this.OutGoingText.Length > 105)
      {
        this.DisplayMessageTooLong();
      }
      else
      {
        var trytesDate = TryteString.FromUtf8String(DateTime.UtcNow.ToString(CultureInfo.InvariantCulture));

        // helps to identify who send the message
        var signature = this.user.PublicKeyAddress.Substring(0, 30);

        // encryption with public key of other user
        var encryptedForContact = this.ntruKex.Encrypt(this.contact.PublicNtruKey, this.OutGoingText);
        var tryteContact = new TryteString(encryptedForContact.ToTrytes() + "9CHIOTAYOUR9" + signature + "9IOTACHATAPP9" + trytesDate + "9ENDEGUTALLESGUT9");

        // encryption with public key of user
        var encryptedForUser = this.ntruKex.Encrypt(this.user.NtruKeyPair.PublicKey, this.OutGoingText);
        var tryteUser = new TryteString(encryptedForUser.ToTrytes() + "9CHIOTAYOUR9" + signature + "9IOTACHATAPP9" + trytesDate + "9ENDEGUTALLESGUT9");

        await this.SendParallelAsync(tryteContact, tryteUser);
      }

      this.IsBusy = false;
      this.OutGoingText = null;
    }

    private Task SendParallelAsync(TryteString tryteContact, TryteString tryteUser)
    {
      var firstTransaction = this.user.TangleMessenger.SendMessageAsync(tryteContact, this.contact.ChatAdress);
      var secondTransaction = this.user.TangleMessenger.SendMessageAsync(tryteUser, this.contact.ChatAdress);

      return Task.WhenAll(firstTransaction, secondTransaction);
    }

    private async void GetMessagesAsync(ICollection<MessageViewModel> messages)
    {
      while (this.MessageLoop)
      {
        await this.AddNewMessagesAsync(messages);
        await Task.Delay(9000);
      }
    }

    private async Task AddNewMessagesAsync(ICollection<MessageViewModel> messages)
    {
      var encryptedMessages = await this.user.TangleMessenger.GetMessagesAsync(this.contact.ChatAdress);
      var messageList = IotaHelper.FilterChatMessages(encryptedMessages, this.ntruKex, this.user.NtruKeyPair, this.lastPostDate);
      if (messageList != null)
      {
        var sortedMessageList = messageList.OrderBy(o => o.Date).ToList();
        foreach (var message in sortedMessageList)
        {
          // might cause problem when two messages send at the exact same time
          if (message.Date > this.lastPostDate)
          {
            messages.Add(
              new MessageViewModel
                {
                  Text = message.Message,
                  IsIncoming = message.Signature == this.contact.PublicKeyAdress.Substring(0, 30),
                  MessagDateTime = message.Date,
                  ProfileImage = this.profileImageUrl
                });
            this.ScrollToNewMessage();
            this.lastPostDate = message.Date;
          }
        }
      }
    }

    private void ScrollToNewMessage()
    {
      var lastMessage = this.messagesListView?.ItemsSource?.Cast<object>()?.LastOrDefault();

      if (lastMessage != null)
      {
        this.messagesListView.ScrollTo(lastMessage, ScrollToPosition.MakeVisible, true);
      }
    }
  }
}