namespace Chiota.Services.DependencyInjection
{
  using System;
  using System.Collections.Generic;

  using Autofac;
  using Autofac.Core;

  using Chiota.Messenger.Service;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AcceptContact;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Messenger.Usecase.DeclineContact;
  using Chiota.Messenger.Usecase.GetContacts;
  using Chiota.Messenger.Usecase.SendMessage;
  using Chiota.Services.Iota.Repository;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels;
  using Chiota.ViewModels.Classes;

  using Tangle.Net.Repository;

  public static class DependencyResolver
  {
    static DependencyResolver()
    {
      Modules = new List<IModule>();
    }

    public static List<IModule> Modules { get; set; }

    private static IContainer Container { get; set; }

    public static void Init()
    {
      var builder = new ContainerBuilder();

      foreach (var module in Modules)
      {
        builder.RegisterModule(module);
      }

      builder.RegisterModule(new ViewModelInjectionModule());

      builder.RegisterType<UserFactory>().As<IUserFactory>();
      builder.RegisterInstance(new RepositoryFactory().Create()).As<IIotaRepository>();

      builder.RegisterType<TangleMessenger>().As<IMessenger>().PropertiesAutowired();

      builder.RegisterType<AddContactInteractor>().As<IUsecaseInteractor<AddContactRequest, AddContactResponse>>().PropertiesAutowired();
      builder.RegisterType<AddContactViewModel>().As<AddContactViewModel>().PropertiesAutowired();

      builder.RegisterType<GetContactsInteractor>().As<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>()
        .PropertiesAutowired();

      builder.RegisterType<AcceptContactInteractor>().As<IUsecaseInteractor<AcceptContactRequest, AcceptContactResponse>>().PropertiesAutowired();
      builder.RegisterType<DeclineContactInteractor>().As<IUsecaseInteractor<DeclineContactRequest, DeclineContactResponse>>().PropertiesAutowired();

      builder.RegisterType<SendMessageInteractor>().As<IUsecaseInteractor<SendMessageRequest, SendMessageResponse>>().PropertiesAutowired();

      builder.RegisterType<UserService>().As<UserService>().PropertiesAutowired();

      Container = builder.Build();
    }

    public static T Resolve<T>()
    {
      return Container.Resolve<T>();
    }

    public static object Resolve(Type type)
    {
      return Container.Resolve(type);
    }

    public static void Reload()
    {
      Init();
    }
  }
}