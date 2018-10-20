namespace Chiota.Messenger.Repository
{
  using System;
  using System.Collections.Generic;
  using System.Diagnostics.CodeAnalysis;
  using System.Threading.Tasks;

  using RestSharp;

  using Tangle.Net.Repository.Client;

  [ExcludeFromCodeCoverage]
  public class MessengerIotaClient : IIotaClient
  {
      public const string DefaultNodeUri = "https://field.deviota.com:443";//"https://field.deviota.com:443";//https://potato.iotasalad.org:14265

        public MessengerIotaClient(List<string> nodeUris)
    {
      if (nodeUris.Count == 0)
      {
        nodeUris.Add(DefaultNodeUri);
      }

      this.NodeUris = nodeUris;
      this.InternalClient = CreateClient(nodeUris[0]);
    }

    public MessengerIotaClient(List<string> nodeUris, IIotaClient client)
    {
      if (nodeUris.Count == 0)
      {
        nodeUris.Add(DefaultNodeUri);
      }

      this.NodeUris = nodeUris;
      this.InternalClient = client;
    }

    private IIotaClient InternalClient { get; set; }

    private List<string> NodeUris { get; }

    private int NodePointer { get; set; }

    /// <inheritdoc />
    public T ExecuteParameterizedCommand<T>(IReadOnlyCollection<KeyValuePair<string, object>> parameters)
      where T : new()
    {
      try
      {
        return this.InternalClient.ExecuteParameterizedCommand<T>(parameters);
      }
      catch (Exception exception)
      {
        this.HandleException(exception);
        return this.ExecuteParameterizedCommand<T>(parameters);
      }
    }

    /// <inheritdoc />
    public void ExecuteParameterizedCommand(IReadOnlyCollection<KeyValuePair<string, object>> parameters)
    {
      try
      {
        this.InternalClient.ExecuteParameterizedCommand(parameters);
      }
      catch (Exception exception)
      {
        this.HandleException(exception);
        this.ExecuteParameterizedCommand(parameters);
      }
    }

    /// <inheritdoc />
    public async Task<T> ExecuteParameterizedCommandAsync<T>(IReadOnlyCollection<KeyValuePair<string, object>> parameters)
      where T : new()
    {
      try
      {
        return await this.InternalClient.ExecuteParameterizedCommandAsync<T>(parameters);
      }
      catch (Exception exception)
      {
        this.HandleException(exception);
        return await this.ExecuteParameterizedCommandAsync<T>(parameters);
      }
    }

    /// <inheritdoc />
    public async Task ExecuteParameterizedCommandAsync(IReadOnlyCollection<KeyValuePair<string, object>> parameters)
    {
      try
      {
        await this.InternalClient.ExecuteParameterizedCommandAsync(parameters);
      }
      catch (Exception exception)
      {
        this.HandleException(exception);
        await this.ExecuteParameterizedCommandAsync(parameters);
      }
    }

    /// <inheritdoc />
    public T ExecuteParameterlessCommand<T>(string commandName)
      where T : new()
    {
      try
      {
        return this.InternalClient.ExecuteParameterlessCommand<T>(commandName);
      }
      catch (Exception exception)
      {
        this.HandleException(exception);
        return this.ExecuteParameterlessCommand<T>(commandName);
      }
    }

    /// <inheritdoc />
    public async Task<T> ExecuteParameterlessCommandAsync<T>(string commandName)
      where T : new()
    {
      try
      {
        return await this.InternalClient.ExecuteParameterlessCommandAsync<T>(commandName);
      }
      catch (Exception exception)
      {
        this.HandleException(exception);
        return await this.ExecuteParameterlessCommandAsync<T>(commandName);
      }
    }

    private static IIotaClient CreateClient(string uri)
    {
      return new RestIotaClient(new RestClient(uri) { Timeout = 2000 });
    }

    private void HandleException(Exception exception)
    {
      this.NodePointer++;

      if (this.NodePointer >= this.NodeUris.Count)
      {
        throw exception;
      }

      this.InternalClient = CreateClient(this.NodeUris[this.NodePointer]);
    }
  }
}