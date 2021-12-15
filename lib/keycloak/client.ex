defmodule Keycloak.Client do
  @moduledoc """
  Module resposible for creating a properly configured
  `OAuth2.Client` for use with the Keycloak configuration.

  ## Configuration

      config :keycloak,
             realm: <REALM>
             site: <KEYCLOAK SERVER URL>
             client_id: <CLIENT_ID>
             client_secret: <CLIENT SECRET>
  """

  alias OAuth2.Client

  @spec config() :: keyword()
  defp config() do
    config =
      Application.get_all_env(:keycloak)

    {realm, config} =
      Keyword.pop(config, :realm)

    {site, config} =
      Keyword.pop(config, :site)

    [
      strategy: Keycloak,
      realm: realm,
      site: "#{site}/auth",
      authorize_url: "/realms/#{realm}/protocol/openid-connect/auth",
      token_url: "/realms/#{realm}/protocol/openid-connect/token",
      serializers: %{"application/json" => Jason}
    ]
    |> Keyword.merge(config)
  end

  @doc """
  Returns a new `OAuth2.Client` ready to make requests to the configured
  Keycloak server.
  """
  @spec new(keyword()) :: OAuth2.Client.t()
  def new(opts \\ []) do
    config()
    |> Keyword.merge(opts)
    |> Client.new()
  end

  @spec logout_url(keyword()) :: String.t()
  def logout_url(params) do
    realm =
      Keyword.get(config(), :realm)

    site =
      Keyword.get(config(), :site)

    "#{site}/realms/#{realm}/protocol/openid-connect/logout"
    |> URI.parse()
    |> may_put_logout_params(params)
    |> URI.to_string()
  end

  defp may_put_logout_params(uri, []), do: uri
  defp may_put_logout_params(uri, params) do
    Map.put(uri, :query, URI.encode_query(params))
  end

  @spec account_url() :: String.t()
  def account_url do
    realm =
      Keyword.get(config(), :realm)

    site =
      Keyword.get(config(), :site)

    "#{site}/realms/#{realm}/account"
    |> URI.parse()
    |> URI.to_string()
  end

  @doc """
  Fetches the current user profile from the Keycloak userinfo endpoint. The
  passed `client` must have already been authorized and have a valid access token.
  """
  @spec me(OAuth2.Client.t()) :: {:ok, OAuth2.Response.t()} | {:error, String.t()}
  def me(%Client{} = client) do
    realm =
      config()
      |> Keyword.get(:realm)

    client
    |> Client.put_header("accept", "application/json")
    |> Client.get("/realms/#{realm}/protocol/openid-connect/userinfo")
  end

  @spec discovery_document(OAuth2.Client.t()) :: {:ok, OAuth2.Response.t()} | {:error, String.t()}
  def discovery_document(%Client{} = client) do
    realm =
      config()
      |> Keyword.get(:realm)

    client
    |> Client.put_header("accept", "application/json")
    |> Client.get("/realms/#{realm}/.well-known/openid-configuration")
  end

  @spec jwks(OAuth2.Client.t()) :: {:ok, OAuth2.Response.t()} | {:error, String.t()}
  def jwks(%Client{} = client) do
    realm =
      config()
      |> Keyword.get(:realm)

    client
    |> Client.put_header("accept", "application/json")
    |> Client.get("/realms/#{realm}/protocol/openid-connect/certs")
  end
end
