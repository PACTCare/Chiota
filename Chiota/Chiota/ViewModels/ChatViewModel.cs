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

  using Xamarin.Forms;

  public class ChatViewModel : BaseViewModel
  {
    public Action DisplayMessageTooLong;

    private readonly string profileImageUrl;

    private readonly User user;

    private readonly Contact contact;

    private readonly NtruKex ntruKex;

    private int postedCount;

    private string outgoingText;

    private ObservableCollection<MessageViewModel> messagesList;

    public ChatViewModel(Contact contact, User user)
    {
      this.ntruKex = new NtruKex();

      this.profileImageUrl = contact.ImageUrl;
      this.user = user;
      this.contact = contact;

      var trytes = this.user.TangleMessenger.GetMessages(this.contact.PublicKeyAdress);
      var contactInfos = IotaHelper.FilterRequestInfos(trytes);
      contact.PublicNtruKey = contactInfos.PublicNtruKey;

      this.Messages = new ObservableCollection<MessageViewModel>();

      this.GetMessagesAsync(this.Messages);

      this.OutGoingText = null;
      this.SendCommand = new Command(async () => { await this.SendMessage(); });
    }

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
      var firstTransaction = this.user.TangleMessenger.SendMessage(tryteContact, this.contact.ChatAdress);
      var secondTransaction = this.user.TangleMessenger.SendMessage(tryteUser, this.contact.ChatAdress);

      return Task.WhenAll(firstTransaction, secondTransaction);
    }

    private async void GetMessagesAsync(ICollection<MessageViewModel> messages)
    {
      while (true)
      {
        this.AddNewMessages(messages);
        await Task.Delay(8000);
      }
    }

    private void AddNewMessages(ICollection<MessageViewModel> messages)
    {
      var decryptedMessages = this.user.TangleMessenger.GetMessages(this.contact.ChatAdress);
      var messageList = IotaHelper.FilterChatMessages(decryptedMessages, this.ntruKex, this.user.NtruKeyPair);
      if (messageList != null)
      {
        var sortedMessageList = messageList.OrderBy(o => o.Date).ToList();
        for (var i = 0; i < sortedMessageList.Count; i++)
        {
          if (i >= this.postedCount)
          {
            messages.Add(
              new MessageViewModel
              {
                Text = sortedMessageList[i].Message,
                IsIncoming = sortedMessageList[i].Signature == this.contact.PublicKeyAdress.Substring(0, 30),
                MessagDateTime = sortedMessageList[i].Date,
                ProfileImage = this.profileImageUrl
              });
            this.postedCount++;
          }
        }
      }
    }
  }
}