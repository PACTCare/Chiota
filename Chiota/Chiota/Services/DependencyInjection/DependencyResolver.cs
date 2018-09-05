namespace Chiota.Services.DependencyInjection
{
  using System.Collections.Generic;

  using Autofac;
  using Autofac.Core;

  using Chiota.Messenger.Service;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AcceptContact;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Messenger.Usecase.GetContacts;
  using Chiota.Services.Iota.Repository;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels;

  /// <summary>
  /// The dependency resolver.
  /// </summary>
  public static class DependencyResolver
  {
    /// <summary>
    /// Initializes static members of the <see cref="DependencyResolver"/> class.
    /// </summary>
    static DependencyResolver()
    {
      Modules = new List<IModule>();
    }

    /// <summary>
    /// Gets or sets the modules.
    /// </summary>
    public static List<IModule> Modules { get; set; }

    /// <summary>
    /// Gets or sets the container.
    /// </summary>
    private static IContainer Container { get; set; }

    /// <summary>
    /// The init.
    /// </summary>
    public static void Init()
    {
      var builder = new ContainerBuilder();

      builder.RegisterType<UserFactory>().As<IUserFactory>();
      builder.RegisterType<RepositoryFactory>().As<IRepositoryFactory>();

      builder.RegisterType<TangleMessenger>().As<IMessenger>().PropertiesAutowired();

      builder.RegisterType<AddContactInteractor>().As<IUsecaseInteractor<AddContactRequest, AddContactResponse>>().PropertiesAutowired();
      builder.RegisterType<AddContactViewModel>().As<AddContactViewModel>().PropertiesAutowired();

      builder.RegisterType<GetContactsInteractor>().As<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>()
        .PropertiesAutowired();

      builder.RegisterType<AcceptContactInteractor>().As<IUsecaseInteractor<AcceptContactRequest, AcceptContactResponse>>().PropertiesAutowired();

      foreach (var module in Modules)
      {
        builder.RegisterModule(module);
      }

      Container = builder.Build();
    }

    /// <summary>
    /// The resolve.
    /// </summary>
    /// <typeparam name="T">
    /// The type.
    /// </typeparam>
    /// <returns>
    /// The <see cref="T"/>.
    /// </returns>
    public static T Resolve<T>()
    {
      return Container.Resolve<T>();
    }
  }
}