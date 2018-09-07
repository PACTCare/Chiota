﻿using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
  using System.Collections.Generic;
  using System.Collections.ObjectModel;
  using System.Linq;
  using System.Text.RegularExpressions;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Messenger;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.SendMessage;
  using Chiota.Models;
  using Chiota.Presenters;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Iota;
  using Chiota.Services.UserServices;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  using Xamarin.Forms;

  public class ChatViewModel : BaseViewModel
  {
    private readonly Contact contact;

    private readonly NtruKex ntruKex;

    private readonly ListView messagesListView;

    private IAsymmetricKeyPair ntruChatKeyPair;

    private string outgoingText;

    private ObservableCollection<MessageViewModel> messagesList;

    private bool loadNewMessages;

    private int messageNumber;

    public ChatViewModel(ListView messagesListView, Contact contact)
    {
      this.ntruKex = new NtruKex();
      this.contact = contact;
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
      if (this.ntruChatKeyPair == null)
      {
        var pasSalt = await IotaHelper.GetChatPasSalt(UserService.CurrentUser, this.contact.ChatKeyAddress);
        this.ntruChatKeyPair = this.ntruKex.CreateAsymmetricKeyPair(pasSalt.Substring(0, 50), pasSalt.Substring(50, 50));
      }

      this.GetMessagesAsync(this.Messages);
    }

    public void OnDisappearing()
    {
      this.PageIsShown = false;
    }

    public async void MessageRestriction(Entry entry)
    {
      var val = entry.Text;

      if (val?.Length > Constants.MessageCharacterLimit)
      {
        val = val.Remove(val.Length - 1);
        entry.Text = val;
        await this.DisplayAlertAsync("Error", $"Message is too long. Limit is {Constants.MessageCharacterLimit} characters.");
      }
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
              ChatAddress = new Address(this.contact.ChatAddress),
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
        var newMessages = await IotaHelper.GetNewMessages(this.ntruChatKeyPair, this.contact, UserService.CurrentUser.TangleMessenger);
        if (newMessages.Count > 0)
        {
          foreach (var m in newMessages)
          {
            if (messages.Any(message => message.MessagDateTime.Ticks == m.MessagDateTime.Ticks))
            {
              continue;
            }

            messages.Add(m);
            await this.GenerateNewAddress();
          }

          this.ScrollToNewMessage();
        }

        this.loadNewMessages = true;
      }
    }

    private async Task GenerateNewAddress()
    {
      this.messageNumber++;
      if (this.messageNumber >= ChiotaConstants.MessagesOnAddress)
      {
        // next chat address is generated based on decrypted messages to make sure nobody excapt the people chatting know the next address
        // it's also based on an incrementing Trytestring, so if you always send the same messages it won't result in the same next address
        this.loadNewMessages = false;
        var rgx = new Regex("[^A-Z]");
        var incrementPart = Helper.TryteStringIncrement(this.contact.ChatAddress.Substring(0, 15));

        var str = incrementPart + rgx.Replace(this.Messages[this.Messages.Count - 1].Text.ToUpper(), string.Empty)
                                + rgx.Replace(this.Messages[this.Messages.Count - 3].Text.ToUpper(), string.Empty)
                                + rgx.Replace(this.Messages[this.Messages.Count - 2].Text.ToUpper(), string.Empty);
        str = str.Truncate(70);
        this.contact.ChatAddress = str + this.contact.ChatAddress.Substring(str.Length);
        this.messageNumber = 0;
        this.loadNewMessages = true;
        await this.AddNewMessagesAsync(this.Messages);
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